const {getDefaultConfig, mergeConfig} = require('@react-native/metro-config');
const path = require('path');
const extraNodeModules = {
  'common': path.resolve(__dirname + '/../common'),
  'crypto': require.resolve('react-native-quick-crypto'),
  'util': require.resolve('react-native-util'),
  // 'stream': require.resolve('stream-browserify'),
  // 'events': require.resolve('events'),
};
const watchFolders = [
  path.resolve(__dirname + '/../common')
];

/**
 * Metro configuration
 * https://facebook.github.io/metro/docs/configuration
 *
 * @type {import('metro-config').MetroConfig}
 */
const config = {
  resolver: {
    extraNodeModules,
  },
  watchFolders,
};

module.exports = mergeConfig(getDefaultConfig(__dirname), config);
