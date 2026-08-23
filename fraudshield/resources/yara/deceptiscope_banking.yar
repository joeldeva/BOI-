/*
  DeceptiScope offline banking-risk rules.
  These rules identify capability combinations, not malware families.
  A match contributes bounded evidence and never establishes legitimacy.
*/

rule DeceptiScope_OTP_Interception_Primitives
{
  meta:
    title = "OTP interception primitives"
    description = "SMS permissions, receiver or API markers appear together"
    severity = "HIGH"
    risk_category = "credential_theft"
    risk_points = 18
  strings:
    $read_sms = "android.permission.READ_SMS" ascii wide
    $receive_sms = "android.permission.RECEIVE_SMS" ascii wide
    $sms_received = "android.provider.Telephony.SMS_RECEIVED" ascii wide
    $sms_manager = "SmsManager" ascii wide
  condition:
    3 of them
}

rule DeceptiScope_Overlay_Accessibility_Combination
{
  meta:
    title = "Overlay and accessibility automation primitives"
    description = "Draw-over-apps and accessibility-control markers appear together"
    severity = "HIGH"
    risk_category = "payment_manipulation"
    risk_points = 20
  strings:
    $overlay = "android.permission.SYSTEM_ALERT_WINDOW" ascii wide
    $bind = "android.permission.BIND_ACCESSIBILITY_SERVICE" ascii wide
    $service = "AccessibilityService" ascii wide
    $gesture = "dispatchGesture" ascii wide
    $global = "performGlobalAction" ascii wide
  condition:
    $overlay and 2 of ($bind, $service, $gesture, $global)
}

rule DeceptiScope_Runtime_Code_Concealment
{
  meta:
    title = "Runtime code-loading and concealment primitives"
    description = "Dynamic loading is paired with reflection or process execution"
    severity = "MEDIUM"
    risk_category = "evasion_resilience"
    risk_points = 12
  strings:
    $loader1 = "DexClassLoader" ascii wide
    $loader2 = "InMemoryDexClassLoader" ascii wide
    $reflection1 = "java/lang/reflect" ascii wide
    $reflection2 = "getDeclaredMethod" ascii wide
    $exec1 = "ProcessBuilder" ascii wide
    $exec2 = "Runtime;->exec" ascii wide
  condition:
    1 of ($loader*) and 1 of ($reflection*, $exec*)
}

rule DeceptiScope_Installed_App_Targeting
{
  meta:
    title = "Installed application discovery primitives"
    description = "The package can enumerate applications and query broad package visibility"
    severity = "MEDIUM"
    risk_category = "payment_manipulation"
    risk_points = 9
  strings:
    $query = "android.permission.QUERY_ALL_PACKAGES" ascii wide
    $installed1 = "getInstalledApplications" ascii wide
    $installed2 = "getInstalledPackages" ascii wide
  condition:
    $query and 1 of ($installed*)
}
