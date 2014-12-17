Package.describe({
  name: 'davidsichau:meteor-lti-auth',
  summary: 'A package to get autentification info from a lti consumer (like moodle) in you lti provider',
  version: '1.0.0',
  git: 'https://github.com/DavidSichau/meteor-lti-auth.git'
});

Package.onUse(function(api) {
  api.versionsFrom('1.0.1');
  api.add_files(['davidsichau:meteor-lti-auth.js'],'server');
});

Package.onTest(function(api) {
  api.use('tinytest');
  api.use('davidsichau:meteor-lti-auth');
  api.addFiles('davidsichau:meteor-lti-auth-tests.js');
});
