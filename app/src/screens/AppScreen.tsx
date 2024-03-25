import React from 'react';
import ZUPASS from '../images/zupass.png';
import GITCOIN from '../images/gitcoin.png';
import { ScrollView, Text, YStack } from 'tamagui';
import AppCard from '../components/AppCard';
import { App, gitcoin, soulbound, zuzalu } from '../utils/AppClass';
import { Steps } from '../utils/utils';
import { Coins, Flame, Ticket } from '@tamagui/lucide-icons';

interface AppScreenProps {
  selectedApp: App | null;
  setSelectedApp: (app: App | null) => void;
  step: number;
  setStep: (step: number) => void;
  setSelectedTab: (tab: string) => void;
}

const AppScreen: React.FC<AppScreenProps> = ({ selectedApp, setSelectedApp, step, setStep, setSelectedTab }) => {

  const handleCardSelect = (app: App) => {
    setSelectedApp(app);
    setStep(Steps.APP_SELECTED);
    setSelectedTab("prove");
  };

  const age = () => (
    <YStack ml="$2" p="$2" px="$3" bc="#2b1400" borderRadius="$10">
      <Text color="#f7670a" fontWeight="bold">age</Text>
    </YStack>
  );
  const comingSoon = () => (
    <YStack ml="$2" p="$2" px="$3" bc="#282828" borderRadius="$10">
      <Text color="#a0a0a0" fontWeight="bold">coming soon</Text>
    </YStack>
  );
  const nationality = () => (
    <YStack ml="$2" p="$2" px="$3" bc="#0d1e18" borderRadius="$10">
      <Text color="#3bb178" fow="bold">nationality</Text>
    </YStack>
  );



  const cardsData = [
    {
      app: zuzalu,
      title: 'Zupass',
      description: 'Connect to prove your identity at in person events',
      background: ZUPASS,
      colorOfTheText: 'white',
      selectable: false,
      icon: Ticket,
      tags: [comingSoon()]
    },
    {
      app: gitcoin,
      title: 'Gitcoin passport',
      description: 'Add to Gitcoin passport and donate to your favorite projects',
      background: GITCOIN,
      colorOfTheText: 'white',
      selectable: false,
      icon: Coins,
      tags: [comingSoon()]
    },
    {
      app: soulbound,
      title: 'Soul Bond Token',
      description: 'Mint a Soul Bond Token and prove you\'re a human',
      colorOfTheText: 'black',
      selectable: true,
      icon: Flame,
      tags: [age(), nationality()]
    }
  ];

  return (
    <ScrollView >
      < YStack my="$4" gap="$5" px="$5" jc="center" alignItems='center' >
        {
          cardsData.map(card => (
            <AppCard
              key={card.app.id}
              title={card.title}
              description={card.description}
              id={card.app.id}
              onTouchStart={() => handleCardSelect(card.app)}
              selected={selectedApp && selectedApp.id === card.app.id ? true : false}
              selectable={card.selectable}
              icon={card.icon}
              tags={card.tags}
            />
          ))
        }

      </YStack >
    </ScrollView >
  );
}

export default AppScreen;
