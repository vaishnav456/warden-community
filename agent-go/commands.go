package main

import (
	"fmt"
)

var operationWhitelist = map[string]bool{
	"INSTALL_APP":               true,
	"UNINSTALL_APP":             true,
	"CREATE_USER":               true,
	"PROVISION_WARDEN_IDENTITY": true,
	"WARDEN_ONLY_LOCKDOWN":      true,
	"DELETE_USER":               true,
	"RESET_PASSWORD":            true,
	"DISABLE_USER":              true,
	"ENABLE_USER":               true,
	"GRANT_ELEVATION":           true,
	"REVOKE_ELEVATION":          true,
	"RUN_CMD":                   true,
	"REBOOT":                    true,
	"SHUTDOWN":                  true,
	"COLLECT_SYSINFO":           true,
	"COLLECT_SOFTWARE":          true,
	"UPDATE_AGENT":              true,
	"SET_PERIPHERAL_POLICY":     true,
	"SETUP_REMOTE_ACCESS":       true,
	"REMOVE_REMOTE_ACCESS":      true,
	"COMPLIANCE_SCAN":           true,
	"FILE_PUSH":                 true,
	"FILE_PULL":                 true,
	"LIST_DIRECTORY":            true,
	"GET_EVENT_LOGS":            true,
	"WINDOWS_UPDATE":            true,
	"UNINSTALL_AGENT":           true,
	"REINSTALL_AGENT":           true,
	"PUSH_LOCAL_POLICY":         true,
	"CHECK_POLICY_DRIFT":        true,
	"COLLECT_USERS":             true,
	"ROTATE_TLS_PINS":           true,
	"CONFIGURE_DEVICE_IDENTITY": true,
	"CAPTURE_PACKETS":           true,
	"COLLECT_NETWORK_FLOWS":     true,
	"SYNC_WARDEN_HOME":          true,
	"WARDEN_HOME_HISTORY":       true,
	"APPLY_DEVICE_EXPERIENCE":   true,
	"ENABLE_BITLOCKER":          true,
	"ROTATE_BITLOCKER_RECOVERY": true,
}

type logFn func(line string)

func dispatchJob(env *Envelope, log logFn) (int, string, error) {
	if !operationWhitelist[env.Operation] {
		return 1, "", fmt.Errorf("operation '%s' is not allowed", env.Operation)
	}
	p := env.Payload
	switch env.Operation {
	case "INSTALL_APP":
		return installApp(env.JobID, p, log)
	case "UNINSTALL_APP":
		return uninstallApp(p)
	case "CREATE_USER":
		return createUser(p)
	case "PROVISION_WARDEN_IDENTITY":
		return provisionWardenIdentity(p)
	case "WARDEN_ONLY_LOCKDOWN":
		return applyWardenOnlyLockdown(p)
	case "DELETE_USER":
		return deleteUser(p)
	case "RESET_PASSWORD":
		return resetPassword(p)
	case "DISABLE_USER":
		return disableUser(p)
	case "ENABLE_USER":
		return enableUser(p)
	case "GRANT_ELEVATION":
		return grantElevation(p)
	case "REVOKE_ELEVATION":
		return revokeElevation(p)
	case "RUN_CMD":
		return runCmdJob(p)
	case "REBOOT":
		return reboot(p)
	case "SHUTDOWN":
		return shutdown(p)
	case "COLLECT_SYSINFO":
		return collectSysinfo()
	case "COLLECT_SOFTWARE":
		return collectSoftware()
	case "UPDATE_AGENT":
		return updateAgent(env.JobID, p, log)
	case "SET_PERIPHERAL_POLICY":
		return setPeripheralPolicy(p)
	case "SETUP_REMOTE_ACCESS":
		return setupRemoteAccess(env.JobID, p)
	case "REMOVE_REMOTE_ACCESS":
		return removeRemoteAccess()
	case "COMPLIANCE_SCAN":
		return complianceScan(env.JobID, p)
	case "FILE_PUSH":
		return filePush(p)
	case "FILE_PULL":
		return filePull(env.JobID, p)
	case "LIST_DIRECTORY":
		return listDirectory(p)
	case "GET_EVENT_LOGS":
		return getEventLogs(env.JobID, p)
	case "WINDOWS_UPDATE":
		return windowsUpdate(p)
	case "UNINSTALL_AGENT":
		return performSelfRemoval()
	case "REINSTALL_AGENT":
		return prepareAgentReinstall(env.JobID, p)
	case "PUSH_LOCAL_POLICY":
		return pushLocalPolicy(p)
	case "CHECK_POLICY_DRIFT":
		var keys []string
		if rawKeys, ok := p["keys"].([]interface{}); ok {
			for _, k := range rawKeys {
				if s, ok := k.(string); ok {
					keys = append(keys, s)
				}
			}
		}
		return checkPolicyDrift(keys)
	case "COLLECT_USERS":
		return collectUsers()
	case "ROTATE_TLS_PINS":
		return rotateTLSPins(p)
	case "CONFIGURE_DEVICE_IDENTITY":
		return configureDeviceIdentity(p)
	case "CAPTURE_PACKETS":
		return capturePackets(env.JobID, p, log)
	case "COLLECT_NETWORK_FLOWS":
		return collectNetworkFlows()
	case "SYNC_WARDEN_HOME":
		return syncWardenHomeJob(p, env.JobID)
	case "WARDEN_HOME_HISTORY":
		return homeHistoryJob(p)
	case "APPLY_DEVICE_EXPERIENCE":
		return applyDeviceExperience(p)
	case "ENABLE_BITLOCKER":
		return manageBitLocker(env.JobID, false)
	case "ROTATE_BITLOCKER_RECOVERY":
		return manageBitLocker(env.JobID, true)
	}
	return 1, "", fmt.Errorf("unhandled operation: %s", env.Operation)
}
