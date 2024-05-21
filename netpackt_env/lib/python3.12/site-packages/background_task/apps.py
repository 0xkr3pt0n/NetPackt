from django.apps import AppConfig


class BackgroundTasksAppConfig(AppConfig):
    default_auto_field = 'django.db.models.AutoField'
    name = 'background_task'
    from background_task import __version__ as version_info
    verbose_name = 'Background Tasks ({})'.format(version_info)

    def ready(self):
        import background_task.signals  # noqa
