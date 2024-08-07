import React, { useEffect } from 'react';
import "react-native-get-random-values";
import "@ethersproject/shims";
import MainScreen from './src/screens/MainScreen';
import { Buffer } from 'buffer';
import { YStack } from 'tamagui';
import { useToastController } from '@tamagui/toast';
import useNavigationStore from './src/stores/navigationStore';
import { AMPLITUDE_KEY } from '@env';
import * as amplitude from '@amplitude/analytics-react-native';
import useUserStore from './src/stores/userStore';
import * as Font from 'expo-font';
import AppLoading from 'expo-app-loading';

global.Buffer = Buffer;

const customFonts = {
  'Lato-Bold': require('./assets/fonts/Lato-Bold.ttf'),
  'Lato-BoldItalic': require('./assets/fonts/Lato-BoldItalic.ttf'),
  'Lato-Italic': require('./assets/fonts/Lato-Italic.ttf'),
  'Lato-Regular': require('./assets/fonts/Lato-Regular.ttf'),
  'Luciole-Bold-Italic': require('./assets/fonts/Luciole-Bold-Italic.ttf'),
  'Luciole-Bold': require('./assets/fonts/Luciole-Bold.ttf'),
  'Luciole-Regular-Italic': require('./assets/fonts/Luciole-Regular-Italic.ttf'),
  'Luciole-Regular': require('./assets/fonts/Luciole-Regular.ttf'),
};

function App(): JSX.Element {
  const [fontsLoaded, setFontsLoaded] = React.useState(false);

  const toast = useToastController();
  const setToast = useNavigationStore((state) => state.setToast);
  const initUserStore = useUserStore((state) => state.initUserStore);

  const loadFonts = async () => {
    await Font.loadAsync(customFonts);
    setFontsLoaded(true);
  };

  useEffect(() => {
    setToast(toast);
  }, [toast, setToast]);

  useEffect(() => {
    if (AMPLITUDE_KEY) {
      amplitude.init(AMPLITUDE_KEY);
    }
    initUserStore();
  }, []);

  useEffect(() => {
    loadFonts();
  }, []);

  if (!fontsLoaded) {
    return <AppLoading />;
  }

  return (
    <YStack f={1} bc="#161616" h="100%" w="100%">
      <YStack h="100%" w="100%">
        <MainScreen />
      </YStack>
    </YStack>
  );
}

export default App;
