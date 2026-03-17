from .celery_base import CeleryBaseService

__all__ = ['CeleryCombineService']


class CeleryCombineService(CeleryBaseService):

    def __init__(self, **kwargs):
        kwargs['queue'] = 'ansible,celery'
        super().__init__(**kwargs)

