import React, { useState, useEffect } from 'react';
import { YStack, XStack, Text, Button, Tabs, Sheet, Label, Fieldset, Input, Switch, Separator, H3, H2, Image, useWindowDimensions, H4 } from 'tamagui'
import { Scan, UserCheck, HelpCircle, IterationCw, LayoutGrid, VenetianMask, Cog, CheckCircle2, ExternalLink } from '@tamagui/lucide-icons';
import X from '../images/x.png'
import Telegram from '../images/telegram.png'
import Github from '../images/github.png'
import ScanScreen from './ScanScreen';
import ProveScreen from './ProveScreen';
import { Steps } from '../utils/utils';
import AppScreen from './AppScreen';
import { App } from '../utils/AppClass';
import { Linking, Platform, Pressable } from 'react-native';
import { Keyboard } from 'react-native';
import NFC_IMAGE from '../images/nfc.png'

interface MainScreenProps {
  onStartCameraScan: () => void;
  nfcScan: () => void;
  passportData: any;
  disclosure: { [key: string]: boolean };
  handleDisclosureChange: (field: string) => void;
  address: string;
  setAddress: (address: string) => void;
  generatingProof: boolean;
  handleProve: (path: string) => void;
  step: number;
  mintText: string;
  proof: any;
  proofTime: number;
  handleMint: () => void;
  setStep: (step: number) => void;
  passportNumber: string;
  setPassportNumber: (number: string) => void;
  dateOfBirth: string;
  setDateOfBirth: (date: string) => void;
  dateOfExpiry: string;
  setDateOfExpiry: (date: string) => void;
  initCompleted: boolean;
}

const MainScreen: React.FC<MainScreenProps> = ({
  onStartCameraScan,
  nfcScan,
  passportData,
  disclosure,
  handleDisclosureChange,
  address,
  setAddress,
  generatingProof,
  handleProve,
  step,
  mintText,
  proof,
  proofTime,
  handleMint,
  setStep,
  passportNumber,
  setPassportNumber,
  dateOfBirth,
  setDateOfBirth,
  dateOfExpiry,
  setDateOfExpiry,
  initCompleted
}) => {
  const [NFCScanIsOpen, setNFCScanIsOpen] = useState(false);
  const [SettingsIsOpen, setSettingsIsOpen] = useState(false);
  const [HelpIsOpen, setHelpIsOpen] = useState(false);
  const [ens, setEns] = useState<string>('');
  const [selectedTab, setSelectedTab] = useState("scan");
  const [selectedApp, setSelectedApp] = useState<App | null>(null);
  const [brokenCamera, setBrokenCamera] = useState(false);
  const [hideData, setHideData] = useState(false);

  const handleRestart = () => {
    setStep(Steps.MRZ_SCAN);
    setSelectedApp(null)
    setPassportNumber("");
    setDateOfBirth("");
    setDateOfExpiry("");

  }
  const handleSkip = () => {
    setStep(Steps.NFC_SCAN_COMPLETED);
    setPassportNumber("");
    setDateOfBirth("");
    setDateOfExpiry("");

  }
  const handleHideData = () => {
    setHideData(!hideData);
  }
  const handleNFCScan = () => {
    if ((Platform.OS === 'ios')) {
      console.log('ios');
      nfcScan();
    }
    else {
      console.log('android :)');
      setNFCScanIsOpen(true);
      nfcScan();
    }
  }
  useEffect(() => {
    if (passportNumber?.length === 9 && (dateOfBirth?.length === 6 && dateOfExpiry?.length === 6)) {
      setStep(Steps.MRZ_SCAN_COMPLETED);
    }
  }, [passportNumber, dateOfBirth, dateOfExpiry]);

  useEffect(() => {
    let timeoutId: ReturnType<typeof setTimeout>;
    if (step == Steps.MRZ_SCAN_COMPLETED) {
      timeoutId = setTimeout(() => {
        setNFCScanIsOpen(false);
      }, 0);
    }
    else if (step >= Steps.NFC_SCAN_COMPLETED) {
      // Set the timeout and store its ID
      timeoutId = setTimeout(() => {
        setNFCScanIsOpen(false);
      }, 700);
    }
    return () => {
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
    };
  }, [step]);

  // Keyboard management
  const [keyboardVisible, setKeyboardVisible] = useState(false);

  useEffect(() => {
    const showSubscription = Keyboard.addListener('keyboardDidShow', () => {
      setKeyboardVisible(true);
    });
    const hideSubscription = Keyboard.addListener('keyboardDidHide', () => {
      setKeyboardVisible(false);
    });

    return () => {
      showSubscription.remove();
      hideSubscription.remove();
    };
  }, []);

  const { height, width } = useWindowDimensions();

  return (
    <YStack f={1} bc="white" mt={Platform.OS === 'ios' ? "$8" : "$0"} mb={Platform.OS === 'ios' ? "$3" : "$0"}>
      <YStack >
        <XStack jc="space-between" ai="center" px="$3">

          <Button p="$2" py="$3" pr="$7" unstyled onPress={() => setSettingsIsOpen(true)}><Cog /></Button>



          <Text fontSize="$6" fow="bold">
            {selectedTab === "scan" ? "Scan" : (selectedTab === "app" ? "Apps" : "Prove")}
          </Text>

          <Button p="$2" py="$3" pl="$7" unstyled onPress={() => setHelpIsOpen(true)}><HelpCircle /></Button>


        </XStack>
        <Sheet open={NFCScanIsOpen} onOpenChange={setNFCScanIsOpen} modal dismissOnOverlayPress={false} disableDrag animation="medium" snapPoints={[35]}>
          <Sheet.Overlay />
          <Sheet.Frame>
            <YStack gap="$5" f={1} pt="$3">
              <H2 textAlign='center' color="gray">Ready to scan</H2>
              {step >= Steps.NFC_SCAN_COMPLETED ?
                <CheckCircle2
                  size="$8"
                  alignSelf='center'
                  color="#3185FC"
                  animation="quick"
                /> :
                <Image
                  h="$8"
                  w="$8"
                  alignSelf='center'
                  borderRadius={1000}
                  source={{
                    uri: NFC_IMAGE
                  }}
                />
              }
              <Text textAlign='center'>Hold your device near the NFC tag.</Text>
            </YStack>
          </Sheet.Frame>
        </Sheet>

        <Sheet open={SettingsIsOpen} onOpenChange={setSettingsIsOpen} modal animation="medium" snapPoints={[88]}>
          <Sheet.Overlay />
          <Sheet.Frame>
            <YStack p="$3" pb="$5" f={1} gap={height > 750 ? "$3" : "$1"} mb="$1.5">
              <XStack gap="$2" >
                <H2>Settings</H2>
                <Cog mt="$1" alignSelf='center' size="$2" />
              </XStack>
              <Fieldset horizontal>
                <Label width={225} justifyContent="flex-end" htmlFor="name" fow="bold">
                  Broken camera
                </Label>
                <Switch size="$3.5" checked={brokenCamera} onCheckedChange={setBrokenCamera}>
                  <Switch.Thumb animation="bouncy" backgroundColor="white" />
                </Switch>
              </Fieldset>
              {
                brokenCamera &&
                <YStack pl="$3" gap="$1">
                  <Fieldset gap="$4" horizontal>
                    <Label width={160} justifyContent="flex-end" fontSize={13}>
                      Passport Number
                    </Label>
                    <Input h="$3.5" borderColor={passportNumber?.length === 9 ? "green" : "unset"} flex={1} id="passport_number" onChangeText={(text) => setPassportNumber(text.toUpperCase())} value={passportNumber} keyboardType="default" />
                  </Fieldset>
                  <Fieldset gap="$4" horizontal>
                    <Label width={160} justifyContent="flex-end" fontSize={13}>
                      Date of birth (yymmdd)
                    </Label>
                    <Input h="$3.5" borderColor={dateOfBirth?.length === 6 ? "green" : "unset"} flex={1} id="date_of_birth" onChangeText={setDateOfBirth} value={dateOfBirth} keyboardType={Platform.OS == "ios" ? "default" : "number-pad"} />
                  </Fieldset>
                  <Fieldset gap="$4" horizontal>
                    <Label width={160} justifyContent="flex-end" fontSize={13}>
                      Date of expiry (yymmdd)
                    </Label>
                    <Input h="$3.5" borderColor={dateOfExpiry?.length === 6 ? "green" : "unset"} flex={1} id="date_of_expiry" onChangeText={setDateOfExpiry} value={dateOfExpiry} keyboardType={Platform.OS == "ios" ? "default" : "number-pad"} />
                  </Fieldset>
                </YStack>
              }

              <Fieldset horizontal>
                <Label width={225} justifyContent="flex-end" htmlFor="restart" fow="bold">
                  Private mode
                </Label>
                <Switch size="$3.5" checked={hideData} onCheckedChange={handleHideData}>
                  <Switch.Thumb animation="bouncy" backgroundColor="white" />
                </Switch>
              </Fieldset>



              <Fieldset gap="$4" mt="$1" horizontal>
                <Label width={200} justifyContent="flex-end" htmlFor="restart" fow="bold">
                  Restart to step 1
                </Label>
                <Button size="$3.5" ml="$2" onPress={handleRestart}>
                  <IterationCw />
                </Button>
              </Fieldset>

              <Fieldset gap="$4" mt="$1" horizontal>
                <Label width={200} justifyContent="flex-end" htmlFor="skip" fow="bold">
                  Use mock passport data
                </Label>
                <Button size="$3.5" ml="$2" onPress={handleSkip}>
                  <VenetianMask />
                </Button>
              </Fieldset>
              <YStack flex={1} />

              <YStack mb="$0">
                <Button onPress={() => setSettingsIsOpen(false)} w="80%" alignSelf='center'>
                  <Text textAlign='center' fow="bold">Close</Text>
                </Button>
              </YStack>
            </YStack>
          </Sheet.Frame>
        </Sheet>

        <Sheet open={HelpIsOpen} onOpenChange={setHelpIsOpen} modal animation="medium" snapPoints={[88]}>
          <Sheet.Overlay />
          <Sheet.Frame>

            <YStack px="$3" pb="$5" flex={1} >
              <XStack mt="$3" gap="$2">
                <H2>Info</H2>
                <HelpCircle mt="$1" alignSelf='center' size="$2" />
              </XStack>
              <YStack flex={1} jc="space-evenly">

                <YStack >
                  <H4>How do I scan my passport ?</H4>
                  <Text>1. Find the location of the NFC chip of your passport. Most of the time, it will be in the back cover. If you have an American passport, the front and back cover are NFC-protected, so you have to open your passport and scan the back cover from the inside.
                    <Button pl="$1" unstyled h="$1" w="$3" jc="flex-end" onPress={() => Linking.openURL('https://zk-passport.github.io/posts/where-is-my-chip/')}>
                      <ExternalLink color="#3185FC" size={12} />
                    </Button>
                  </Text>
                  <Text mt="$2">2. Find the location of the NFC reader of your phone. On an iPhone, it should be on the upper part of your phone. On Android phones, it should be in the center.
                    <Button pl="$1" unstyled h="$1" w="$3" jc="flex-end" onPress={() => Linking.openURL('https://zk-passport.github.io/posts/locate-NFC-reader/')}>
                      <ExternalLink color="#3185FC" size={12} />
                    </Button>
                  </Text>
                  <Text mt="$2">3. Keep your passport pressed against your phone when the NFC popup shows up and hold still.</Text>
                </YStack>
                <YStack gap="$1">
                  <H4 mt="$2">Security and Privacy</H4>
                  <Text>Proof of Passport uses zero-knowledge cryptography to allow you to prove facts about yourself like humanity, nationality or age without disclosing sensitive information. It works by generating a proof showing your passport data has been correctly signed by a government authority without revealing the signature.</Text>
                </YStack>
                <YStack gap="$2">
                  <H4 mt="$1">What are zero-knowledge proofs ?</H4>

                  <Text>Zero-knowledge proofs rely on mathematical magic tricks to show the correctness of some computation while hiding some inputs of its inputs. In our case, the proof shows the passport has not been forged, but allows you to hide sensitive data.</Text>
                </YStack>

                <YStack gap="$2">
                  <H4 >Contacts</H4>
                  <XStack mt="$2" ml="$3" gap="$5">
                    <Pressable onPress={() => Linking.openURL('https://t.me/proofofpassport')}>
                      <Image
                        source={{ uri: Telegram, width: 24, height: 24 }}
                      />
                    </Pressable>
                    <Pressable onPress={() => Linking.openURL('https://x.com/proofofpassport')}>
                      <Image
                        source={{ uri: X, width: 24, height: 24 }}
                      />
                    </Pressable>
                    <Pressable onPress={() => Linking.openURL('https://github.com/zk-passport/proof-of-passport')}>
                      <Image
                        source={{ uri: Github, width: 24, height: 24 }}
                      />
                    </Pressable>
                  </XStack>
                </YStack>
              </YStack>
              <Button alignSelf='center' w="80%" onPress={() => setHelpIsOpen(false)}>
                <Text w="80%" textAlign='center' fow="bold">Close</Text>
              </Button>

            </YStack>
          </Sheet.Frame>
        </Sheet>



        <Separator />
      </YStack>
      <Tabs f={1} orientation="horizontal" flexDirection="column" defaultValue="scan" onValueChange={setSelectedTab}>
        <Tabs.Content value="scan" f={1}>
          <ScanScreen
            onStartCameraScan={onStartCameraScan}
            handleNFCScan={handleNFCScan}
            step={step} />
        </Tabs.Content>

        <Tabs.Content value="app" f={1}>
          <AppScreen
            selectedApp={selectedApp}
            setSelectedApp={setSelectedApp}
            step={step}
            setStep={setStep}
          />
        </Tabs.Content>

        <Tabs.Content value="generate" f={1}>
          <ProveScreen
            passportData={passportData}
            disclosure={disclosure}
            selectedApp={selectedApp}
            handleDisclosureChange={handleDisclosureChange}
            address={address}
            setAddress={setAddress}
            generatingProof={generatingProof}
            handleProve={handleProve}
            step={step}
            mintText={mintText}
            proof={proof}
            proofTime={proofTime}
            handleMint={handleMint}
            hideData={hideData}
            ens={ens}
            setEns={setEns}
            initCompleted={initCompleted}
          />
        </Tabs.Content>
        <Separator />
        {(!keyboardVisible || Platform.OS == "ios") &&
          <Tabs.List pt="$2" pb="$2">
            <Tabs.Tab value="scan" unstyled w="33%">
              <YStack ai="center">
                <Scan color={selectedTab === "scan" ? '#3185FC' : 'black'} />
                <Text fontSize="$2" color={selectedTab === "scan" ? '#3185FC' : 'black'}>Scan</Text>
              </YStack>
            </Tabs.Tab>
            {step >= Steps.NFC_SCAN_COMPLETED ?
              <Tabs.Tab value="app" unstyled w="33%">
                <YStack ai="center">
                  <LayoutGrid color={selectedTab === "app" ? '#3185FC' : 'black'} />
                  <Text fontSize="$2" color={selectedTab === "app" ? '#3185FC' : 'black'}>Apps</Text>
                </YStack>
              </Tabs.Tab>
              :
              <Tabs.Tab value="scan" unstyled w="33%">
                <YStack ai="center">
                  <LayoutGrid color="#bcbcbc" />
                  <Text fontSize="$2" color="#bcbcbc">Apps</Text>
                </YStack>
              </Tabs.Tab>

            }
            {
              (step >= Steps.NFC_SCAN_COMPLETED) && (selectedApp != null) ?
                <Tabs.Tab value="generate" unstyled w="33%">
                  <YStack ai="center">
                    <UserCheck color={selectedTab === "generate" ? '#3185FC' : 'black'} />
                    <Text fontSize="$2" color={selectedTab === "generate" ? '#3185FC' : 'black'}>Prove</Text>
                  </YStack>
                </Tabs.Tab>
                :
                <Tabs.Tab value={step >= Steps.NFC_SCAN_COMPLETED ? "app" : "scan"} unstyled w="33%">
                  <YStack ai="center">
                    <UserCheck color="#bcbcbc" />
                    <Text fontSize="$2" color="#bcbcbc">Prove</Text>
                  </YStack>
                </Tabs.Tab>
            }
          </Tabs.List>

        }
      </Tabs>
    </YStack >
  );
};

export default MainScreen;
