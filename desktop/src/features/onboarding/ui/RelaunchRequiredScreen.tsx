import { RecoveryScreen } from "./RecoveryScreen";

export function RelaunchRequiredScreen() {
  return (
    <RecoveryScreen
      testId="relaunch-required"
      title="Restart Snowman Command Center to finish recovery"
      body="Your identity was updated. Snowman Command Center needs to restart so syncing and agents run under it."
    />
  );
}
