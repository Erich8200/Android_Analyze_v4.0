import os

# 所有Android权限
system_permission_list = [
    'android.permission.SYSTEM_ALERT_WINDOW',
    'android.permission.WRITE_SETTINGS',
    'android.permission.READ_CALENDAR',
    'android.permission.WRITE_CALENDAR',
    'android.permission.CAMERA',
    'android.permission.READ_CONTACTS',
    'android.permission.WRITE_CONTACTS',
    'android.permission.GET_ACCOUNTS',
    'android.permission.ACCESS_FINE_LOCATION',
    'android.permission.ACCESS_COARSE_LOCATION',
    'android.permission.RECORD_AUDIO',
    'android.permission.READ_PHONE_STATE',
    'android.permission.CALL_PHONE',
    'android.permission.READ_CALL_LOG',
    'android.permission.WRITE_CALL_LOG',
    'com.android.voicemail.permission.ADD_VOICEMAIL',
    'android.permission.USE_SIP',
    'android.permission.PROCESS_OUTGOING_CALLS',
    'android.permission.BODY_SENSORS',
    'android.permission.SEND_SMS',
    'android.permission.RECEIVE_SMS',
    'android.permission.READ_SMS',
    'android.permission.RECEIVE_WAP_PUSH',
    'android.permission.RECEIVE_MMS',
    'android.permission.READ_EXTERNAL_STORAGE',
    'android.permission.WRITE_EXTERNAL_STORAGE',
]

# Android 系统广播
system_broadcast_list = [
    'android.intent.action.AIRPLANE_MODE',
    'android.intent.action.BATTERY_CHANGED',
    'android.intent.action.BATTERY_LOW',
    'android.intent.action.BATTERY_OKAY',
    'android.intent.action.BOOT_COMPLETED',
    'android.intent.action.CAMERA_BUTTON',
    'android.intent.action.CLOSE_SYSTEM_DIALOGS',
    'android.intent.action.CONFIGURATION_CHANGED',
    'android.intent.action.DATE_CHANGED',
    'android.intent.action.DEVICE_STORAGE_LOW',
    'android.intent.action.DEVICE_STORAGE_OK',
    'android.intent.action.DOCK_EVENT',
    'android.intent.action.DREAMING_STARTED',
    'android.intent.action.DREAMING_STOPPED',
    'android.intent.action.EXTERNAL_APPLICATIONS_AVAILABLE',
    'android.intent.action.EXTERNAL_APPLICATIONS_UNAVAILABLE',
    'android.intent.action.GET_RESTRICTION_ENTRIES',
    'android.intent.action.GTALK_CONNECTED',
    'android.intent.action.GTALK_DISCONNECTED',
    'android.intent.action.HEADSET_PLUG',
    'android.intent.action.INPUT_METHOD_CHANGED',
    'android.intent.action.LOCALE_CHANGED',
    'android.intent.action.MANAGE_PACKAGE_STORAGE',
    'android.intent.action.MEDIA_BAD_REMOVAL',
    'android.intent.action.MEDIA_BUTTON',
    'android.intent.action.MEDIA_CHECKING',
    'android.intent.action.MEDIA_EJECT',
    'android.intent.action.MEDIA_MOUNTED',
    'android.intent.action.MEDIA_NOFS',
    'android.intent.action.MEDIA_REMOVED',
    'android.intent.action.MEDIA_SCANNER_FINISHED',
    'android.intent.action.MEDIA_SCANNER_SCAN_FILE',
    'android.intent.action.MEDIA_SCANNER_STARTED',
    'android.intent.action.MEDIA_SHARED',
    'android.intent.action.MEDIA_UNMOUNTABLE',
    'android.intent.action.MEDIA_UNMOUNTED',
    'android.intent.action.MY_PACKAGE_REPLACED',
    'android.intent.action.NEW_OUTGOING_CALL',
    'android.intent.action.PACKAGE_ADDED',
    'android.intent.action.PACKAGE_CHANGED',
    'android.intent.action.PACKAGE_DATA_CLEAREDANGED',
    'android.intent.action.PACKAGE_FIRST_LAUNCH',
    'android.intent.action.PACKAGE_FULLY_REMOVED',
    'android.intent.action.PACKAGE_INSTALL',
    'android.intent.action.PACKAGE_NEEDS_VERIFICATION',
    'android.intent.action.PACKAGE_REMOVED',
    'android.intent.action.PACKAGE_REPLACED',
    'android.intent.action.PACKAGE_RESTARTED',
    'android.intent.action.PACKAGE_VERIFIED',
    'android.intent.action.ACTION_POWER_CONNECTED',
    'android.intent.action.ACTION_POWER_DISCONNECTED',
    'android.intent.action.PROVIDER_CHANGED',
    'android.intent.action.REBOOT',
    'android.intent.action.SCREEN_OFF',
    'android.intent.action.SCREEN_ON',
    'android.intent.action.ACTION_SHUTDOWN',
    'android.intent.action.TIMEZONE_CHANGED',
    'android.intent.action.TIME_SET',
    'android.intent.action.TIME_TICK',
    'android.intent.action.UID_REMOVED',
    'android.intent.action.UMS_CONNECTED',
    'android.intent.action.UMS_DISCONNECTED',
    'android.intent.action.USER_PRESENT',
    'android.intent.action.WALLPAPER_CHANGED',
]

# 从文件中读取数据到list
def read_file_to_list(file_path: str):
    if os.path.exists(file_path):
        output = []
        with open(file_path, 'r+') as file:
            while True:
                line = file.readline()
                if line:
                    output.append(line.strip('\n'))
                else:
                    break
        return output
    return False

def list_to_linear_file(file_path:str, filename: str, list: list, sep):
    with open(file_path + os.sep + filename, "wb") as file:
        for line in list:
            file.write(bytes(line + sep, encoding='utf-8'))