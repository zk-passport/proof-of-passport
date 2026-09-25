// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

import type React from 'react';
import type { GestureResponderEvent, LayoutChangeEvent, PressableProps, ViewStyle } from 'react-native';
import { Platform, Pressable, StyleSheet, Text } from 'react-native';

import type { KnownEventName } from '../../constants/analytics';
import { dinot } from '../../constants/fonts';
import { useSelfClient } from '../../context';
import { pressedStyle } from './pressedStyle';

export interface ButtonProps extends PressableProps {
  children: React.ReactNode;
  animatedComponent?: React.ReactNode;
  trackEvent?: KnownEventName;
  trackEventProperties?: Record<string, unknown>;
  borderWidth?: number;
  borderColor?: string;
  fontSize?: number;
  onLayout?: (event: LayoutChangeEvent) => void;
}

/**
 * Standard interface for extracting style props from button components.
 * Use this to separate style-related props from other button props.
 */
export interface ExtractedButtonStyleProps {
  borderWidth?: number;
  borderColor?: string;
  fontSize?: number;
}

interface AbstractButtonProps extends ButtonProps {
  bgColor: string;
  borderColor?: string;
  borderWidth?: number;
  fontSize?: number;
  color: string;
}

// Helper to extract border props from style object
function extractBorderFromStyle(style: ViewStyle | undefined): {
  borderColor?: string;
  borderWidth?: number;
  restStyle: ViewStyle;
} {
  if (!style) return { restStyle: {} };
  const { borderColor, borderWidth, ...restStyle } = style;
  return { borderColor: borderColor as string | undefined, borderWidth, restStyle };
}

/*
    Base Button component that can be used to create different types of buttons
    use PrimaryButton and SecondaryButton instead of this component or create a new button component

    @dev If the button isnt filling the space check that its parent is 100% width
*/
export default function AbstractButton({
  children,
  bgColor,
  color,
  borderColor: propBorderColor,
  borderWidth: propBorderWidth,
  fontSize,
  style,
  animatedComponent,
  trackEvent,
  trackEventProperties,
  onPress,
  ...props
}: AbstractButtonProps) {
  const selfClient = useSelfClient();

  // Extract border from style prop if provided there
  const flatStyle = StyleSheet.flatten(style) as ViewStyle | undefined;
  const { borderColor: styleBorderColor, borderWidth: styleBorderWidth, restStyle } = extractBorderFromStyle(flatStyle);

  // Props take precedence over style
  const borderColor = propBorderColor ?? styleBorderColor;
  const borderWidth = propBorderWidth ?? styleBorderWidth;
  const hasBorder = borderColor != null;

  const handlePress = (e: GestureResponderEvent) => {
    if (trackEvent) {
      selfClient.trackEvent(trackEvent, trackEventProperties);
    }
    if (onPress) {
      onPress(e);
    }
  };

  return (
    <Pressable
      {...props}
      onPress={handlePress}
      style={({ pressed }) => [
        styles.container,
        { backgroundColor: bgColor },
        hasBorder
          ? {
              borderWidth: borderWidth ?? 1,
              borderColor: borderColor,
            }
          : Platform.select({ web: { borderWidth: 0 }, default: {} }),
        !animatedComponent && pressed ? pressedStyle : {},
        restStyle as ViewStyle,
      ]}
    >
      {animatedComponent}
      <Text allowFontScaling={false} style={[styles.text, { color, fontSize: fontSize ?? 18 }]}>
        {children}
      </Text>
    </Pressable>
  );
}

const styles = StyleSheet.create({
  container: {
    position: 'relative',
    justifyContent: 'center',
    flexDirection: 'row',
    flexGrow: 0,
    flexShrink: 0,
    width: '100%',
    display: 'flex',
    alignItems: 'center',
    rowGap: 12,
    padding: 20,
    borderRadius: 5,
  },
  text: {
    fontFamily: dinot,
    textAlign: 'center',
    fontSize: 18,
  },
});
