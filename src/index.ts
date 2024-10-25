import { NativeModules, Platform } from 'react-native';

const LINKING_ERROR =
  `The package 'react-native-biometrics' doesn't seem to be linked. Make sure: \n\n` +
  Platform.select({ ios: "- You have run 'pod install'\n", default: '' }) +
  '- You rebuilt the app after installing the package\n' +
  '- You are not using Expo Go\n';

const bridge = NativeModules.Biometrics
  ? NativeModules.Biometrics
  : new Proxy(
      {},
      {
        get() {
          throw new Error(LINKING_ERROR);
        },
      }
    );

/**
 * Type alias for possible biometry types
 */
export type BiometryType = 'TouchID' | 'FaceID' | 'Biometrics';

/**
 * Only for Android
 * https://developer.android.com/reference/androidx/biometric/BiometricManager#constants_1
 */
export enum IsSensorAvailableErrorCode {
  BIOMETRIC_ERROR_HW_UNAVAILABLE = 1,
  BIOMETRIC_ERROR_NONE_ENROLLED = 11,
  BIOMETRIC_ERROR_NO_HARDWARE = 12,
  BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED = 15,
  BIOMETRIC_ERROR_UNSUPPORTED = -2,
  BIOMETRIC_STATUS_UNKNOWN = -1,
}

/**
 * Only for Android
 * https://developer.android.com/reference/androidx/biometric/BiometricPrompt#constants_1
 */
export enum AndroidPromptErrorCode {
  ERROR_CANCELED = 5,
  ERROR_HW_NOT_PRESENT = 12,
  ERROR_HW_UNAVAILABLE = 1,
  ERROR_LOCKOUT = 7,
  ERROR_LOCKOUT_PERMANENT = 9,
  ERROR_MORE_OPTIONS_BUTTON = 16,
  ERROR_NEGATIVE_BUTTON = 13,
  ERROR_NO_BIOMETRICS = 11,
  ERROR_NO_DEVICE_CREDENTIAL = 14,
  ERROR_NO_SPACE = 4,
  ERROR_SECURITY_UPDATE_REQUIRED = 15,
  ERROR_TIMEOUT = 3,
  ERROR_UNABLE_TO_PROCESS = 2,
  ERROR_USER_CANCELED = 10,
  ERROR_VENDOR = 8,
}

interface RNBiometricsOptions {
  allowDeviceCredentials?: boolean;
}

interface IsSensorAvailableResult {
  available: boolean;
  biometryType?: BiometryType;
  error?: string;
  errorCode?: IsSensorAvailableErrorCode | number;
}

interface CreateKeysResult {
  publicKey: string;
}

interface BiometricKeysExistResult {
  keysExist: boolean;
}

interface DeleteKeysResult {
  keysDeleted: boolean;
}

interface CreateSignatureOptions {
  promptMessage: string;
  payload: string;
  cancelButtonText?: string;
}

export type PromptErrorCodeType = AndroidPromptErrorCode | number | string;

interface CreateSignatureResult {
  success: boolean;
  signature?: string;
  error?: string;
  errorCode?: PromptErrorCodeType;
}

interface SimplePromptOptions {
  promptMessage: string;
  fallbackPromptMessage?: string;
  cancelButtonText?: string;
}

interface SimplePromptResult {
  success: boolean;
  error?: string;
  errorCode?: PromptErrorCodeType;
}

/**
 * Enum for touch id sensor type
 */
export const TouchID = 'TouchID';
/**
 * Enum for face id sensor type
 */
export const FaceID = 'FaceID';
/**
 * Enum for generic biometrics (this is the only value available on android)
 */
export const Biometrics = 'Biometrics';

export const BiometryTypes = {
  TouchID,
  FaceID,
  Biometrics,
};

export default class ReactNativeBiometrics {
  allowDeviceCredentials = false;

  /**
   * @param {Object} rnBiometricsOptions
   * @param {boolean} rnBiometricsOptions.allowDeviceCredentials
   */
  constructor(rnBiometricsOptions?: RNBiometricsOptions) {
    const allowDeviceCredentials =
      rnBiometricsOptions?.allowDeviceCredentials ?? false;
    this.allowDeviceCredentials = allowDeviceCredentials;
  }

  /**
   * Returns promise that resolves to an object with object.biometryType = Biometrics | TouchID | FaceID
   * @returns {Promise<Object>} Promise that resolves to an object with details about biometrics available
   */
  isSensorAvailable(): Promise<IsSensorAvailableResult> {
    return bridge.isSensorAvailable({
      allowDeviceCredentials: this.allowDeviceCredentials,
    });
  }

  /**
   * Creates a public private key pair,returns promise that resolves to
   * an object with object.publicKey, which is the public key of the newly generated key pair
   * @returns {Promise<Object>}  Promise that resolves to object with details about the newly generated public key
   */
  createKeys(): Promise<CreateKeysResult> {
    return bridge.createKeys({
      allowDeviceCredentials: this.allowDeviceCredentials,
    });
  }

  /**
   * Returns promise that resolves to an object with object.keysExists = true | false
   * indicating if the keys were found to exist or not
   * @returns {Promise<Object>} Promise that resolves to object with details aobut the existence of keys
   */
  biometricKeysExist(): Promise<BiometricKeysExistResult> {
    return bridge.biometricKeysExist();
  }

  /**
   * Returns promise that resolves to an object with true | false
   * indicating if the keys were properly deleted
   * @returns {Promise<Object>} Promise that resolves to an object with details about the deletion
   */
  deleteKeys(): Promise<DeleteKeysResult> {
    return bridge.deleteKeys();
  }

  /**
   * Prompts user with biometrics dialog using the passed in prompt message and
   * returns promise that resolves to an object with object.signature,
   * which is cryptographic signature of the payload
   * @param {Object} createSignatureOptions
   * @param {string} createSignatureOptions.promptMessage
   * @param {string} createSignatureOptions.payload
   * @returns {Promise<Object>}  Promise that resolves to an object cryptographic signature details
   */
  createSignature(
    createSignatureOptions: CreateSignatureOptions
  ): Promise<CreateSignatureResult> {
    createSignatureOptions.cancelButtonText =
      createSignatureOptions.cancelButtonText ?? 'Cancel';

    return bridge.createSignature({
      allowDeviceCredentials: this.allowDeviceCredentials,
      ...createSignatureOptions,
    });
  }

  /**
   * Prompts user with biometrics dialog using the passed in prompt message and
   * returns promise that resolves to an object with object.success = true if the user passes,
   * object.success = false if the user cancels, and rejects if anything fails
   * @param {Object} simplePromptOptions
   * @param {string} simplePromptOptions.promptMessage
   * @param {string} simplePromptOptions.fallbackPromptMessage
   * @returns {Promise<Object>}  Promise that resolves an object with details about the biometrics result
   */
  simplePrompt(
    simplePromptOptions: SimplePromptOptions
  ): Promise<SimplePromptResult> {
    simplePromptOptions.cancelButtonText =
      simplePromptOptions.cancelButtonText ?? 'Cancel';
    simplePromptOptions.fallbackPromptMessage =
      simplePromptOptions.fallbackPromptMessage ?? 'Use Passcode';

    return bridge.simplePrompt({
      allowDeviceCredentials: this.allowDeviceCredentials,
      ...simplePromptOptions,
    });
  }

  /**
   * Dismisses the biometrics dialog created by createSignature or simplePrompt
   */
  cancelPrompt(): void {
    return bridge.cancelPrompt();
  }
}
