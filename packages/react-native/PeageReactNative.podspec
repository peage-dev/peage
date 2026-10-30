require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "PeageReactNative"
  s.version      = package["version"]
  s.summary      = "App Attest Turbo Module for Péage"
  s.homepage     = "https://peage.dev"
  s.license      = "MIT"
  s.authors      = { "Péage" => "say.hi@peage.dev" }
  s.platforms    = { :ios => min_ios_version_supported }
  s.source       = { :git => "https://github.com/peage-dev/peage.git", :tag => "#{s.version}" }
  s.source_files = "ios/**/*.{h,m,mm,swift}"

  install_modules_dependencies(s)
end
