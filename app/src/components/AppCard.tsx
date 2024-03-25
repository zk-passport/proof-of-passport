import React from 'react';
import { Text, YStack, XStack, H4, Button } from 'tamagui';
import { ChevronRight } from '@tamagui/lucide-icons';
import Toast from 'react-native-toast-message';
import { borderColor, componentBgColor, textColor1, textColor2 } from '../utils/colors';


interface AppCardProps {
    title: string;
    description: string;
    id: string | number;
    onTouchStart?: () => void;
    selected?: boolean;
    selectable?: boolean;
    icon: any;
    tags: any;
}

const AppCard: React.FC<AppCardProps> = ({
    title,
    description,
    id,
    onTouchStart,
    selected,
    selectable,
    icon,
    tags
}) => {
    const showtoast = () => {
        Toast.show({
            type: 'info',
            text1: '🚧 Coming soon ',
            position: 'top',
            topOffset: 80,
        })
    }

    return (
        <YStack
            overflow="hidden"
            elevation={selected ? "$3" : "$3"}
            borderRadius="$7"
            borderWidth={1.2}
            borderColor={borderColor}
            key={id}
            bg={componentBgColor}
        >
            <YStack p="$2.5">
                <XStack gap="$3" ai="center">
                    <XStack h="$3" w="$3" p="$1" ai="center" jc="center" bc="#232323" borderWidth={1.2} borderColor="#343434" borderRadius="$3">
                        {React.createElement(icon, { color: textColor1 })}
                    </XStack>
                    <YStack width={250}>
                        <H4 color={textColor1} selectable={false} >{title}</H4>
                    </YStack>
                    <XStack flex={1} />
                </XStack>
            </YStack>
            <YStack p="$2" bc="#232323" borderWidth={1.2} borderLeftWidth={0} borderRightWidth={0} borderColor="#343434">
                <XStack ai="center">
                    <YStack gap="$1" >
                        <Text color={textColor2} mt="$1" theme="alt2" selectable={false}>{description}.</Text>
                        <Text color={textColor2} mt="$1" theme="alt2" selectable={false}>No other data that the ones selected in the next step will be shared with the app.</Text>
                    </YStack>
                    <XStack flex={1} />
                </XStack>
            </YStack>
            <YStack p="$2">
                <XStack gap="$4" ai="center">
                    <XStack gap="$1">
                        {tags.map((Tag: any, index: any) => <React.Fragment key={index}>{Tag}</React.Fragment>)}
                    </XStack>
                    <XStack f={1} />
                    <Button h="$3" p="$2" pl="$3" borderRadius="$4" borderWidth={1} backgroundColor="#282828" borderColor="#343434" onPress={selectable ? onTouchStart : showtoast}>
                        <XStack gap="$0">
                            <Text color="#ededed" fontSize="$5"  >Select</Text>
                            <ChevronRight size="$1" color="#ededed" />
                        </XStack>
                    </Button>
                </XStack>
            </YStack>

        </YStack>

    );
}

export default AppCard;
