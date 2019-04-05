workflow "Make release" {
  resolves = ["JasonEtco/upload-to-release@master", "JasonEtco/upload-to-release@master-1"]
  on = "release"
}

action "codehz/arch-cmake-builder@master" {
  uses = "codehz/arch-cmake-builder@master"
  args = "CC=musl-gcc"
}

action "JasonEtco/upload-to-release@master" {
  uses = "JasonEtco/upload-to-release@master"
  needs = ["codehz/arch-cmake-builder@master"]
  args = "build/ezbin application/x-executable"
  secrets = ["GITHUB_TOKEN"]
}

action "JasonEtco/upload-to-release@master-1" {
  uses = "JasonEtco/upload-to-release@master"
  needs = ["codehz/arch-cmake-builder@master"]
  args = "build/ezio application/x-executable"
  secrets = ["GITHUB_TOKEN"]
}

workflow "Test build" {
  resolves = ["codehz/arch-cmake-builder@master-1"]
  on = "push"
}

action "codehz/arch-cmake-builder@master-1" {
  uses = "codehz/arch-cmake-builder@master"
  args = "CC=musl-gcc"
}
