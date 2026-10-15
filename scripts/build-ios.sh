#!/bin/bash
set -euo pipefail
project_dir="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$project_dir/.build"
mode="${1:-simulator}"
case "$mode" in
  simulator)
    xcodebuild -project "$project_dir/armanVPN-IOS.xcodeproj" -scheme armanVPN-IOS \
      -configuration Debug -destination 'generic/platform=iOS Simulator' \
      -derivedDataPath "$project_dir/.build/simulator" CODE_SIGNING_ALLOWED=NO build
    ;;
  unsigned)
    xcodebuild -project "$project_dir/armanVPN-IOS.xcodeproj" -scheme armanVPN-IOS \
      -configuration Debug -destination 'generic/platform=iOS' \
      -derivedDataPath "$project_dir/.build/unsigned" CODE_SIGNING_ALLOWED=NO build
    ;;
  device)
    xcodebuild -project "$project_dir/armanVPN-IOS.xcodeproj" -scheme armanVPN-IOS \
      -configuration Debug -destination 'generic/platform=iOS' \
      -derivedDataPath "$project_dir/.build/device" \
      -allowProvisioningUpdates -allowProvisioningDeviceRegistration build
    ;;
  *) printf 'Usage: bash scripts/build-ios.sh [simulator|unsigned|device]\n' >&2; exit 2 ;;
esac
