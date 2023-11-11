#ifndef _CONFIG_H_
#define _CONFIG_H_

//#define _DEBUG
//#define _VM_CHECK

#define __VERSION__ 0
#define __GROUP__ L""

#define DECRYPT_KEY 0x00000000

#define CONTROL_PANEL L""
#define REPEATER_LIST L""

#define REPEATER_URI L""
#define TELEMETRY_URI L""

#define REPEATER_PORT 0
#define FILESERVER_PORT 0
#define TELEMETRY_PORT 0

#ifdef _DEBUG
    #define PING_INTERVAL 0
#else
    #define PING_INTERVAL 0
#endif

#define LAUNCHER_NAME L""
#define PLUGIN_DIR L""
#define MUTEX_NAME L""
#define MACHINE_ID_KEY L""

#define SERVICE_NAME L""
#define SERVICE_DISPLAY_NAME L""

#define REGISTRY_NAME L""

#endif /* !_CONFIG_H_ */