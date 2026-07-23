Pod::Spec.new do |s|
  s.name             = 'VeraFraudSdk'
  s.version          = '0.1.0'
  s.summary          = 'Vera fraud SDK native modules (call-signal detection)'
  s.description      = 'Native collectors for @veratools/fraud-sdk-expo.'
  s.author           = 'Vera Tools'
  s.homepage         = 'https://verawall.com'
  s.license          = { :type => 'MIT' }
  s.platforms        = { :ios => '15.1' }
  s.swift_version    = '5.9'
  s.source           = { :git => '' }
  s.static_framework = true

  s.dependency 'ExpoModulesCore'

  s.source_files = '**/*.{h,m,swift}'
end
