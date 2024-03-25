import React from 'react';
import { YStack, Text, XStack, Button } from 'tamagui';
import { Steps } from '../utils/utils';
import { Camera, ExternalLink, Nfc } from '@tamagui/lucide-icons';

interface ScanScreenProps {
  onStartCameraScan: () => void;
  handleNFCScan: () => void;
  step: number;
}

const ScanScreen: React.FC<ScanScreenProps> = ({ onStartCameraScan, handleNFCScan, step }) => {

  return (
    <YStack f={1} p="$5" gap="$5" px="$5" justifyContent='center'>

      <YStack bc="#1c1c1c" borderWidth={1.2} borderColor="#343434" borderRadius="$6">
        <YStack p="$3">
          <XStack gap="$4" ai="center">
            <XStack p="$2" bc="#232323" borderWidth={1.2} borderColor="#343434" borderRadius="$3">
              <Camera color="#a0a0a0" />
            </XStack>
            <YStack gap="$1">
              <Text fontSize={16} fow="bold" color="#ededed">Step 1</Text>
              <Text color="#a0a0a0">Scan you passport </Text>
            </YStack>
          </XStack>
        </YStack>
        <YStack gap="$2" p="$3" bc="#232323" borderWidth={1.2} borderLeftWidth={0} borderRightWidth={0} borderColor="#343434">
          <Text color="#7e7e7e">Use the camera to scan main page of your passport.</Text>
          <Text color="#7e7e7e">No personnal data will be stored or shared with external apps.</Text>
        </YStack>
        <YStack p="$2">
          <XStack gap="$4" ai="center">
            {step >= Steps.MRZ_SCAN_COMPLETED ? (
              <XStack ml="$2" p="$2" px="$3" bc="#0d1e18" borderRadius="$10">
                <Text color="#3bb178" fow="bold">Done</Text>
              </XStack>
            ) : (
              <XStack ml="$2" p="$2" px="$3" bc="#2b1400" borderRadius="$10">
                <Text color="#f7670a" fow="bold">To-do</Text>
              </XStack>
            )}
            <XStack f={1} />
            <Button h="$3" onPress={onStartCameraScan} p="$2" borderRadius="$4" borderWidth={1} backgroundColor="#282828" borderColor="#343434">
              <XStack gap="$2">
                <Text color="#ededed" fontSize="$5" >Open camera</Text>
                <ExternalLink size="$1" color="#ededed" />
              </XStack>
            </Button>
          </XStack>
        </YStack>
      </YStack >

      <YStack bc="#1c1c1c" borderWidth={1.2} borderColor="#343434" borderRadius="$6">
        <YStack p="$3">
          <XStack gap="$4" ai="center">
            <XStack p="$2" bc="#232323" borderWidth={1.2} borderColor="#343434" borderRadius="$3">
              <Nfc color="#a0a0a0" />
            </XStack>
            <YStack gap="$1">
              <Text fontSize={16} fow="bold" color="#ededed">Step 2</Text>
              <Text color="#a0a0a0">Read the NFC chip </Text>
            </YStack>
          </XStack>
        </YStack>
        <YStack gap="$2" p="$3" bc="#232323" borderWidth={1.2} borderLeftWidth={0} borderRightWidth={0} borderColor="#343434">
          <Text color="#7e7e7e">Hold your passport against your device to read the biometric chip.</Text>
          <Text color="#7e7e7e">No personnal data will be stored or shared with external apps.</Text>
        </YStack>
        <YStack p="$2">
          <XStack gap="$4" ai="center">
            {step < Steps.MRZ_SCAN_COMPLETED ? (
              <YStack ml="$2" p="$2" px="$3" bc="#282828" borderRadius="$10">
                <Text color="#a0a0a0" fontWeight="bold">To-do</Text>
              </YStack>
            ) : step < Steps.NFC_SCAN_COMPLETED ? (
              <XStack ml="$2" p="$2" px="$3" bc="#2b1400" borderRadius="$10">
                <Text color="#f7670a" fow="bold">To-do</Text>
              </XStack>
            ) : (
              <XStack ml="$2" p="$2" px="$3" bc="#0d1e18" borderRadius="$10">
                <Text color="#3bb178" fow="bold">Done</Text>
              </XStack>
            )}
            <XStack f={1} />
            <Button h="$3" onPress={handleNFCScan} p="$2" borderRadius="$4" borderWidth={1} backgroundColor="#282828" borderColor="#343434">
              <XStack gap="$2">
                <Text color={step < Steps.MRZ_SCAN_COMPLETED ? "#343434" : "#ededed"} fontSize="$5"  >Scan with NFC</Text>
                <ExternalLink size="$1" color={step < Steps.MRZ_SCAN_COMPLETED ? "#343434" : "#ededed"} />
              </XStack>
            </Button>
          </XStack>
        </YStack>
      </YStack >



      {/* 
      <XStack
        jc="center"
        borderColor="#a0a0a0"
        borderWidth={1}
        borderRadius="$10"
        f={0}
        w="$1.5"
        h="$1.5"
        alignSelf='center'>
        <Text color="#a0a0a0" fontSize="$4" y={0} x={0} alignSelf='center'>1</Text>
      </XStack>
      <Text color="#a0a0a0" fontSize="$6" textAlign='center' mt="$2"  >Scan the machine readable zone on the main page of your passport</Text> */}

      {/* <XStack
        mt="$10"
        jc="center"
        borderColor="#a0a0a0"
        borderWidth={1}
        borderRadius="$10"
        f={0}
        w="$1.5"
        h="$1.5"
        alignSelf='center'>
        <Text color="#a0a0a0" fontSize="$4" y={0} x={0} alignSelf='center'>2</Text>
      </XStack>
      <Text color="#a0a0a0" fontSize="$6" textAlign='center' mt="$2" >Hold your passport against your device to read the biometric chip</Text> */}
      {/* 
      <YStack ai="center">
        {
          step < Steps.NFC_SCAN_COMPLETED
            ? (
              step < Steps.MRZ_SCAN_COMPLETED
                ?
                <YStack mt="$6">
                  <Button borderWidth={1} backgroundColor="#282828" borderColor="#343434" variant="outlined">
                    <Camera color="#ededed" />
                    <Text color="#ededed" fontSize="$6" onPress={onStartCameraScan} >Open camera</Text>
                  </Button>
                  <Spinner mt="$4" color={step === Steps.NFC_SCANNING ? "#3185FC" : "transparent"} />

                </YStack>
                : (
                  <YStack mt="$6">
                    <Text p="$6" fontSize="$6" color="#3185FC" onPress={handleNFCScan}>
                      {step === Steps.NFC_SCANNING ? "Scanning" : "Scan passport with NFC"}
                    </Text>
                    <Spinner mt="$4" color={step === Steps.NFC_SCANNING ? "#3185FC" : "transparent"} />
                  </YStack>
                )
            )
            :
            <XStack />
        }
      </YStack> */}
    </YStack >
  );
};

export default ScanScreen;
