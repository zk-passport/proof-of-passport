import React, { useState, useEffect } from 'react';
import { NativeModules } from 'react-native';
import { YStack, XStack, Text, Checkbox, Input, Button, Spinner, Image, useWindowDimensions } from 'tamagui';
import { Check, LayoutGrid, Scan, Copy } from '@tamagui/lucide-icons';
import { getFirstName, formatDuration } from '../../utils/utils';
import { attributeToPosition } from '../../../common/src/constants/constants';
import { Steps } from '../utils/utils';
import USER from '../images/user.png'
import arkzkeyUrl from '../../deployments/arkzkeyUrl.json'
import ProofGrid from '../components/ProofGrid';
import { App } from '../utils/AppClass';
import { Keyboard, Platform } from 'react-native';
import { DEFAULT_ADDRESS } from '@env';
const { ethers } = require('ethers');
import Clipboard from '@react-native-community/clipboard';
import Toast from 'react-native-toast-message';

const fileName = "proof_of_passport_final.arkzkey"
const path = "/data/user/0/com.proofofpassport/files/" + fileName

interface ProveScreenProps {
  selectedApp: App | null;
  passportData: any;
  disclosure: { [key: string]: boolean };
  handleDisclosureChange: (field: string) => void;
  address: string;
  setAddress: (address: string) => void;
  generatingProof: boolean;
  handleProve: (path: string) => void;
  handleMint: () => void;
  step: number;
  mintText: string;
  proof: { proof: string, inputs: string } | null;
  proofTime: number;
  hideData: boolean;
  ens: string;
  setEns: (ens: string) => void;
  initCompleted: boolean;
}

const ProveScreen: React.FC<ProveScreenProps> = ({
  passportData,
  disclosure,
  selectedApp,
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
  hideData,
  ens,
  setEns,
  initCompleted
}) => {
  const [zkeyLoading, setZkeyLoading] = useState(false);
  const [zkeyLoaded, setZkeyLoaded] = useState(false);

  const getTx = (input: string | null): string => {
    if (!input) return '';
    const transaction = input.split(' ').filter(word => word.startsWith('0x')).join(' ');
    return transaction;
  }
  const shortenInput = (input: string | null): string => {
    if (!input) return '';
    if (input.length > 9) {
      return input.substring(0, 25) + '\u2026';
    } else {
      return input;
    }
  }

  const copyToClipboard = (input: string) => {
    Clipboard.setString(input);
    Toast.show({
      type: 'success',
      text1: '🖨️ Tx copied to clipboard',
      position: 'top',
      bottomOffset: 80,
    })
  };

  const downloadZkey = async () => {
    // TODO: don't redownload if already in the file system at path, if downloaded from previous session
    setZkeyLoading(true);
    // Allow the spinner to show up before app freeze on android
    await new Promise(resolve => setTimeout(resolve, 1500));
    try {
      console.log('Downloading file...')
      const result = await NativeModules.RNPassportReader.downloadFile(
        arkzkeyUrl.arkzkeyUrl,
        fileName
      );
      console.log("Download successful");
      console.log(result);
      setZkeyLoaded(true);
      setZkeyLoading(false);
    } catch (e: any) {
      console.log("Download not successful");
      Toast.show({
        type: 'error',
        text1: `Error: ${e.message}`,
        position: 'top',
        bottomOffset: 80,
      })
      setZkeyLoading(false);
    }
  };

  const maskString = (input: string): string => {
    if (input.length <= 5) {
      return input.charAt(0) + '*'.repeat(input.length - 1);
    } else {
      return input.charAt(0) + input.charAt(1) + '*'.repeat(input.length - 2);
    }
  }



  const [inputValue, setInputValue] = useState(DEFAULT_ADDRESS ?? '');
  const provider = new ethers.JsonRpcProvider(`https://eth-mainnet.g.alchemy.com/v2/lpOn3k6Fezetn1e5QF-iEsn-J0C6oGE0`);

  useEffect(() => {
    if (ens != '' && inputValue == '') {
      setInputValue(ens);

    }
    else if (address != ethers.ZeroAddress && inputValue == '') {
      setInputValue(address);
    }

  }, [])

  useEffect(() => {
    const resolveENS = async () => {
      if (inputValue != ens) {
        if (inputValue.endsWith('.eth')) {
          try {
            Toast.show({
              type: 'info',
              text1: '🔭 Looking for ' + inputValue,
              position: 'top',
              bottomOffset: 80,
            })
            const resolvedAddress = await provider.resolveName(inputValue);
            if (resolvedAddress) {
              console.log("new address settled:" + resolvedAddress);
              setAddress(resolvedAddress);
              setEns(inputValue);
              Toast.show({
                type: 'success',
                text1: '🎊 welcome ' + inputValue,
                position: 'top',
                bottomOffset: 90,
              })
              if (hideData) {
                console.log(maskString(address));
                //  setInputValue(maskString(address));
              }
              else {
                // setInputValue(address);
              }
            } else {
              Toast.show({
                type: 'error',
                text1: '❌  ' + inputValue + ' not found ',
                position: 'top',
                bottomOffset: 90,
              })
            }
          } catch (error) {
            Toast.show({
              type: 'error',
              text1: 'Error resolving ENS name',
              text2: 'Check input format or RPC provider',
              position: 'top',
              bottomOffset: 80,
            })
          }
        }
        else if (inputValue.length === 42 && inputValue.startsWith('0x')) {
          setAddress(inputValue);
        }
      };
    };

    resolveENS();
  }, [inputValue]);




  // Keyboard management
  const [keyboardVisible, setKeyboardVisible] = useState(false);
  const { height, width } = useWindowDimensions();
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

  return (
    <YStack px="$4" f={1} >
      {(step >= Steps.NFC_SCAN_COMPLETED && selectedApp != null) ?
        (step < Steps.PROOF_GENERATED ? (
          <YStack flex={1} mx="$2" gap="$2">
            <YStack alignSelf='center' my="$3">
              {hideData ?
                <Image
                  w={height > 750 ? 150 : 100}
                  h={height > 750 ? 190 : 80}
                  borderRadius={height > 800 ? "$11" : "$9"}
                  source={{
                    uri: USER,
                  }}
                /> :
                <Image
                  w={height > 750 ? 150 : 110}
                  h={height > 750 ? 190 : 130}
                  borderRadius={height > 750 ? "$11" : "$9"}
                  source={{
                    uri: passportData.photoBase64 ?? USER,
                  }}
                />

              }
            </YStack>
            <Text fontSize="$5" fontWeight="bold">Hi {hideData ? maskString(getFirstName(passportData.mrz)) : getFirstName(passportData.mrz)} 👋</Text>
            <Text >Enter your address or ens:</Text>
            <Input
              fontSize={13}
              placeholder="anon.eth or 0x023…"
              value={inputValue}
              onChangeText={setInputValue}
              autoCorrect={false}
              autoCapitalize='none'
              borderColor={address != ethers.ZeroAddress ? "#3185FC" : "unset"}
            />

            <YStack f={1} >
              <Text h="$3" mt="$2">{selectedApp?.disclosurephrase}</Text>
              <YStack mt="$1">
                {selectedApp && Object.keys(selectedApp.disclosure).map((key) => {
                  const key_ = key as string;
                  const indexes = attributeToPosition[key_];
                  const keyFormatted = key_.replace(/_/g, ' ').split(' ').map((word: string) => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
                  const mrzAttribute = passportData.mrz.slice(indexes[0], indexes[1] + 1);
                  const mrzAttributeFormatted = mrzAttribute;

                  return (
                    <XStack key={key} mx="$2" gap="$4" alignItems='center'>
                      <XStack p="$2" onPress={() => handleDisclosureChange(key_)}>
                        <Checkbox
                          value={key}
                          checked={disclosure[key_]}
                          onCheckedChange={() => handleDisclosureChange(key_)}
                          aria-label={keyFormatted}
                          size="$5"
                        >
                          <Checkbox.Indicator >
                            <Check />
                          </Checkbox.Indicator>
                        </Checkbox>
                      </XStack>
                      <Text fontWeight="bold">{keyFormatted}: </Text>
                      <Text>{hideData ? maskString(mrzAttributeFormatted) : mrzAttributeFormatted}</Text>
                    </XStack>
                  );
                })}
              </YStack>
            </YStack>
            <XStack f={1} />
            <XStack f={1} />
            <XStack f={1} />
            {
              (!keyboardVisible || Platform.OS == "ios") && (
              <Button
                disabled={zkeyLoading || address == ethers.ZeroAddress || (!initCompleted && Platform.OS == "ios")}
                borderRadius={100}
                onPress={
                  () => {
                    (!zkeyLoaded && Platform.OS != "ios")
                      ? downloadZkey()
                      : handleProve(path)
                  }
                }
                mt="$8"
                backgroundColor={address == ethers.ZeroAddress ? "#cecece" : "#3185FC"}
                alignSelf='center'
              >
                {!zkeyLoaded && Platform.OS != "ios" ? (
                  <XStack ai="center" gap="$2">
                    {zkeyLoading && <Spinner />}
                    <Text color="white" fow="bold">{zkeyLoading ? "Downloading ZK circuit" : "Download ZK circuit"}</Text>
                  </XStack>
                ) : !initCompleted && Platform.OS == "ios" ? (
                  <Text color="white" fow="bold">Initializing...</Text>
                ) : generatingProof ? (
                  <XStack ai="center" gap="$1">
                    <Spinner />
                    <Text color="white" marginLeft="$2" fow="bold" >Generating ZK proof</Text>
                  </XStack>
                ) : (
                  <Text color="white" fow="bold">Generate ZK proof</Text>
                )}

              </Button>
              )
            }
            {(height > 750) && <Text fontSize={10} color={generatingProof ? "gray" : "white"} pb="$2" alignSelf='center'>This operation can take up to 2 mn, phone may freeze during this time</Text>}
          </YStack>

        ) : step === Steps.TX_MINTED ? (
          <YStack flex={1} justifyContent='center' alignItems='center' gap="$5">
            <XStack flex={1} />
            <ProofGrid proof={proof} />

            <YStack gap="$1">
              <Text fontWeight="bold" fontSize="$6" mt="$5">Congrats 🎉x2</Text>
              <Text fontWeight="bold" fontSize="$5" >You just have minted a Soulbond token !</Text>
              <Text color="gray" fontSize="$4" fow="bold" textAlign='left'>You can now share this proof with the selected app.</Text>

              <Text color="gray" fontSize="$4" fow="bold" mt="$5">Network: Sepolia</Text>
              <XStack jc='space-between' h="$2" ai="center">
                <Text fontWeight="bold" fontSize="$5">Tx: {shortenInput(getTx(mintText))}</Text>
              </XStack>
            </YStack>

            <XStack flex={1} />
            <Button borderRadius={100} onPress={() => copyToClipboard(getTx(mintText))} marginTop="$4" mb="$8" backgroundColor="#3185FC">
              <Copy color="white" size="$1" /><Text color="white" fow="bold" >Copy to clipboard</Text>
            </Button>

          </YStack>
        ) : (
          <YStack flex={1} justifyContent='center' alignItems='center' gap="$5">
            <XStack flex={1} />
            <ProofGrid proof={proof} />

            <YStack>
              <Text fontWeight="bold" fontSize="$6" mt="$6">Congrats 🎉</Text>
              <Text fontWeight="bold" fontSize="$5" mt="$1.5">You just generated this Zero Knowledge proof !</Text>
              <Text color="gray" fontSize="$5" mt="$1" fow="bold" textAlign='left'>You can now share this proof with the selected app.</Text>
              <Text color="gray" mt="$3">Proof generation duration: {formatDuration(proofTime)}</Text>
            </YStack>
            <XStack flex={1} />
            <Button disabled={step === Steps.TX_MINTING} borderRadius={100} onPress={handleMint} marginTop="$4" mb="$8" backgroundColor="#3185FC">
              {step === Steps.TX_MINTING ?
                <XStack gap="$2">
                  <Spinner />
                  <Text color="white" fow="bold" > Minting </Text>
                </XStack>
                : <Text color="white" fow="bold" >{selectedApp?.mintphrase}</Text>}
            </Button>

          </YStack>
        )

        ) :
        (
          <YStack flex={1} justifyContent='center' alignItems='center'>
            <Text fontSize={17} textAlign='center' fow="bold">Please scan your passport and select an app to generate ZK proof</Text>
            <XStack mt="$8" gap="$7">
              <Scan size="$4" color={step < Steps.NFC_SCAN_COMPLETED ? "black" : "#3185FC"} />
              <LayoutGrid size="$4" color={selectedApp == null ? "black" : "#3185FC"} />
            </XStack>
          </YStack>

        )
      }
    </YStack >
  );
};
export default ProveScreen;     
