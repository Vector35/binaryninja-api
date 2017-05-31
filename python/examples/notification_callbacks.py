from binaryninja import BinaryDataNotification, PluginCommand, log_info
import inspect

def reg_notif(view):
    demo_notification = DemoNotification(view)
    view.register_notification(demo_notification)

class DemoNotification(BinaryDataNotification):
    def __init__(self, view):
        self.view = view

    def data_written(self, *args):
        log_info(inspect.stack()[0][3] + str(args))

    def data_inserted(self, *args):
        log_info(inspect.stack()[0][3] + str(args))

    def data_removed(self, *args):
        log_info(inspect.stack()[0][3] + str(args))

    def function_added(self, *args):
        log_info(inspect.stack()[0][3] + str(args))

    def function_removed(self, *args):
        log_info(inspect.stack()[0][3] + str(args))

    def function_updated(self, *args):
        log_info(inspect.stack()[0][3] + str(args))

    def data_var_added(self, *args):
        log_info(inspect.stack()[0][3] + str(args))

    def data_var_updated(self, *args):
        log_info(inspect.stack()[0][3] + str(args))

    def data_var_removed(self, *args):
        log_info(inspect.stack()[0][3] + str(args))

    def string_found(self, *args):
        log_info(inspect.stack()[0][3] + str(args))

    def string_removed(self, *args):
        log_info(inspect.stack()[0][3] + str(args))

    def type_defined(self, *args):
        log_info(inspect.stack()[0][3] + str(args))

    def type_undefined(self, *args):
        log_info(inspect.stack()[0][3] + str(args))

PluginCommand.register("Register Notification", "", reg_notif)
