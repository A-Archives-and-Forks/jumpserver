import asyncio
import contextlib
import shutil
import socket
import struct
import time

import netifaces

from settings.utils import generate_ips, generate_ports

_ETHERTYPE_IPV4 = 0x0800
_PACKET_ALL = 0x0003
_READ_TIMEOUT = 0.25
_STOP_TIMEOUT = 1


def list_show(items, default='all'):
    return ','.join(map(str, items)) or default


def _build_or_filter(template, values):
    if not values:
        return ''
    clauses = [template.format(value=value) for value in values]
    if len(clauses) == 1:
        return clauses[0]
    return f"({' or '.join(clauses)})"


def build_tcpdump_filter(src_ips, src_ports, dest_ips, dest_ports):
    filters = [
        _build_or_filter('src host {value}', src_ips),
        _build_or_filter('src port {value}', src_ports),
        _build_or_filter('dst host {value}', dest_ips),
        _build_or_filter('dst port {value}', dest_ports),
    ]
    return ' and '.join(filter(None, filters))


def _format_endpoint(ip, port):
    try:
        service = socket.getservbyport(port, 'tcp')
    except OSError:
        service = str(port)
    return f'{ip}.{service}'


def _format_tcp_flags(flags):
    mapping = (
        (0x01, 'F'),
        (0x02, 'S'),
        (0x04, 'R'),
        (0x08, 'P'),
        (0x10, '.'),
        (0x20, 'U'),
        (0x40, 'E'),
        (0x80, 'W'),
    )
    text = ''.join(symbol for bit, symbol in mapping if flags & bit)
    return text or 'none'


def _format_emulated_line(src_ip, src_port, dest_ip, dest_port, seq, ack, flags, win, payload_len):
    now = time.time()
    timestamp = time.strftime('%H:%M:%S', time.localtime(now))
    micros = int((now % 1) * 1_000_000)
    details = [f'Flags [{_format_tcp_flags(flags)}]']
    if payload_len:
        details.append(f'seq {seq}:{seq + payload_len}')
    elif flags & 0x07:
        details.append(f'seq {seq}')
    if flags & 0x10:
        details.append(f'ack {ack}')
    details.append(f'win {win}')
    details.append(f'length {payload_len}')
    return (
        f'{timestamp}.{micros:06d} IP '
        f'{_format_endpoint(src_ip, src_port)} > {_format_endpoint(dest_ip, dest_port)}: '
        f"{', '.join(details)}"
    )


async def once_tcpdump_emulated(
        interface, src_ips, src_ports, dest_ips, dest_ports, display, stop_event
):
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(_PACKET_ALL))
    sock.bind((interface, 0))
    sock.setblocking(False)
    try:
        while not stop_event.is_set():
            try:
                packet = await asyncio.wait_for(loop.sock_recv(sock, 65535), timeout=_READ_TIMEOUT)
            except asyncio.TimeoutError:
                continue

            if len(packet) < 54:
                continue

            ether_type = struct.unpack('!H', packet[12:14])[0]
            if ether_type != _ETHERTYPE_IPV4:
                continue

            version_ihl = packet[14]
            if version_ihl >> 4 != 4:
                continue
            ip_header_len = (version_ihl & 0x0F) * 4
            tcp_offset = 14 + ip_header_len
            if len(packet) < tcp_offset + 20:
                continue

            ip_header = packet[14:14 + ip_header_len]
            ip_hdr = struct.unpack('!BBHHHBBH4s4s', ip_header[:20])
            if ip_hdr[6] != socket.IPPROTO_TCP:
                continue

            tcp_header = packet[tcp_offset:tcp_offset + 20]
            tcp_hdr = struct.unpack('!HHLLBBHHH', tcp_header)
            src_ip, dest_ip = map(socket.inet_ntoa, ip_hdr[8:10])
            src_port, dest_port = tcp_hdr[0], tcp_hdr[1]

            if src_ips and src_ip not in src_ips:
                continue
            if src_ports and src_port not in src_ports:
                continue
            if dest_ips and dest_ip not in dest_ips:
                continue
            if dest_ports and dest_port not in dest_ports:
                continue

            tcp_header_len = (tcp_hdr[4] >> 4) * 4
            total_length = ip_hdr[2]
            payload_len = max(total_length - ip_header_len - tcp_header_len, 0)
            await display(
                _format_emulated_line(
                    src_ip, src_port, dest_ip, dest_port,
                    tcp_hdr[2], tcp_hdr[3], tcp_hdr[5], tcp_hdr[6], payload_len
                )
            )
    finally:
        sock.close()


async def once_tcpdump(
        interface, src_ips, src_ports, dest_ips, dest_ports, display, stop_event, tcpdump_path
):
    command = [tcpdump_path, '-l', '-i', interface]
    capture_filter = build_tcpdump_filter(src_ips, src_ports, dest_ips, dest_ports)
    if capture_filter:
        command.append(capture_filter)

    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    wait_task = asyncio.create_task(process.wait())

    try:
        while not stop_event.is_set():
            try:
                line = await asyncio.wait_for(process.stdout.readline(), timeout=_READ_TIMEOUT)
            except asyncio.TimeoutError:
                if wait_task.done():
                    break
                continue

            if not line:
                if wait_task.done():
                    break
                continue

            message = line.decode(errors='replace').rstrip()
            if message:
                await display(message)
    finally:
        if process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(wait_task, timeout=_STOP_TIMEOUT)
            except asyncio.TimeoutError:
                process.kill()
                await wait_task
        else:
            await wait_task

    if process.returncode and not stop_event.is_set():
        await display(f'Error: tcpdump exited with status {process.returncode}')


def _get_valid_interfaces(interfaces):
    all_interfaces = netifaces.interfaces()
    if not interfaces:
        return all_interfaces
    requested = set(interfaces)
    return [name for name in all_interfaces if name in requested]


async def verbose_tcpdump(
        interfaces, src_ips, src_ports, dest_ips, dest_ports, display=None, stop_event=None
):
    if not display:
        return

    stop_event = stop_event or asyncio.Event()
    valid_interfaces = _get_valid_interfaces(interfaces)
    if interfaces and not valid_interfaces:
        await display('Error: no valid network interface was selected')
        return

    src_ips = generate_ips(src_ips)
    src_ports = generate_ports(src_ports)
    dest_ips = generate_ips(dest_ips)
    dest_ports = generate_ports(dest_ports)

    summary = [
        '[Summary] Tcpdump filter info: ',
        f'Interface: [{list_show(valid_interfaces)}]',
        f'Source address: [{list_show(src_ips)}]',
        f'source port: [{list_show(src_ports)}]',
        f'Destination address: [{list_show(dest_ips)}]',
        f'Destination port: [{list_show(dest_ports)}]',
    ]
    for line in summary:
        await display(line)

    tcpdump_path = shutil.which('tcpdump')
    if not tcpdump_path:
        await display('[Warning] tcpdump command not found, using limited built-in capture mode')
        tasks = [
            asyncio.create_task(
                once_tcpdump_emulated(
                    interface, src_ips, src_ports, dest_ips, dest_ports, display, stop_event
                )
            )
            for interface in valid_interfaces
        ]
    else:
        tasks = [
            asyncio.create_task(
                once_tcpdump(
                    interface, src_ips, src_ports, dest_ips, dest_ports,
                    display, stop_event, tcpdump_path
                )
            )
            for interface in valid_interfaces
        ]

    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        stop_event.set()
        raise
    finally:
        stop_event.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task
