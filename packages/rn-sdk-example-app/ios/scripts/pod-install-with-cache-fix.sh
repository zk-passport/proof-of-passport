#!/bin/bash

# Pod install with hermes-engine cache fix for React Native upgrades
# This script handles CocoaPods cache mismatches that occur after React Native version upgrades

set -e  # Exit on any error

echo "Clearing CocoaPods cache to prevent hermes-engine version conflicts..."
bundle exec pod cache clean --all > /dev/null 2>&1 || true
rm -rf ~/Library/Caches/CocoaPods > /dev/null 2>&1 || true

echo "Attempting pod install..."
if bundle exec pod install; then
  echo "Pods installed successfully"
else
  echo "Pod install failed, likely due to hermes-engine cache mismatch after React Native upgrade"
  echo "Running targeted fix: bundle exec pod update hermes-engine..."
  bundle exec pod update hermes-engine --no-repo-update
  echo "Retrying pod install..."
  bundle exec pod install
  echo "Pods installed successfully after cache fix"
fi
