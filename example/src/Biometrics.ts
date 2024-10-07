import { Platform } from 'react-native';
import ReactNativeBiometrics, {
  type BiometryType,
  IsSensorAvailableErrorCode,
  AndroidPromptErrorCode,
  type PromptErrorCodeType,
} from 'react-native-biometrics';

const throwBiometricError = (
  errorCode?: PromptErrorCodeType,
  errorMessage?: string
) => {
  if (errorCode !== undefined) {
    const errorCodeString = `${errorCode}`;
    const error = new Error(errorMessage || errorCodeString);
    error.code = errorCodeString;
    throw error;
  }

  if (errorMessage !== undefined) {
    const error = new Error(errorMessage);
    error.code = errorMessage;
    throw error;
  }

  const error = new Error('Unknown error');
  error.code = 'UNKNOWN';
  throw error;
};

export const getBiometricSensorStatus: () => Promise<{
  available: boolean;
  permissionsDenied: boolean;
  biometryType?: BiometryType;
}> = async () => {
  try {
    const rnBiometrics = new ReactNativeBiometrics();

    const { available, biometryType, error, errorCode } =
      await rnBiometrics.isSensorAvailable();

    if (!!errorCode || !!error || !available || !biometryType) {
      throwBiometricError(errorCode, error);
    }

    return { available: true, permissionsDenied: false, biometryType };
  } catch (e: any) {
    console.error(`getBiometricSensorStatus ${e}`, e.code);
    if (Platform.OS === 'ios') {
      switch (e?.code) {
        case '-8': // -8 = Too many attempts
          return { available: true, permissionsDenied: false };
        case '-6': // -6 = FaceID permission denied
          return { available: false, permissionsDenied: true };
        case '-7': // -7 = No biometrics enrolled
        default:
          return { available: false, permissionsDenied: false };
      }
    } else {
      switch (e?.code) {
        case IsSensorAvailableErrorCode.BIOMETRIC_ERROR_HW_UNAVAILABLE.toString():
        case IsSensorAvailableErrorCode.BIOMETRIC_ERROR_NONE_ENROLLED.toString():
        case IsSensorAvailableErrorCode.BIOMETRIC_ERROR_NO_HARDWARE.toString():
        case IsSensorAvailableErrorCode.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED.toString():
        case IsSensorAvailableErrorCode.BIOMETRIC_ERROR_UNSUPPORTED.toString():
        case IsSensorAvailableErrorCode.BIOMETRIC_STATUS_UNKNOWN.toString():
        default:
          return { available: false, permissionsDenied: false };
      }
    }
  }
};

export enum BiometricPromptError {
  PERMISSIONS_DENIED = 'PERMISSIONS_DENIED',
  TOO_MANY_ATTEMPTS = 'TOO_MANY_ATTEMPTS',
  USER_CANCELLED = 'USER_CANCELLED',
  KEY_INVALIDATED = 'KEY_INVALIDATED',
  GENERIC = 'GENERIC',
}

const handlePromptErrors = (e: Error) => {
  if (Platform.OS === 'ios') {
    switch (e.code) {
      case '-8':
        return BiometricPromptError.TOO_MANY_ATTEMPTS;
      case '-6':
        return BiometricPromptError.PERMISSIONS_DENIED;
      case '-4':
      case '-2':
        return BiometricPromptError.USER_CANCELLED;
      default:
        return BiometricPromptError.GENERIC;
    }
  } else {
    switch (e.code) {
      case AndroidPromptErrorCode.ERROR_CANCELED.toString():
      case AndroidPromptErrorCode.ERROR_USER_CANCELED.toString():
      case AndroidPromptErrorCode.ERROR_NEGATIVE_BUTTON.toString():
        return BiometricPromptError.USER_CANCELLED;
      case AndroidPromptErrorCode.ERROR_LOCKOUT.toString():
      case AndroidPromptErrorCode.ERROR_LOCKOUT_PERMANENT.toString():
        return BiometricPromptError.TOO_MANY_ATTEMPTS;
      case 'KeyPermanentlyInvalidatedException':
        return BiometricPromptError.KEY_INVALIDATED;
      case AndroidPromptErrorCode.ERROR_HW_NOT_PRESENT.toString():
      case AndroidPromptErrorCode.ERROR_HW_UNAVAILABLE.toString():
      case AndroidPromptErrorCode.ERROR_MORE_OPTIONS_BUTTON.toString():
      case AndroidPromptErrorCode.ERROR_NO_BIOMETRICS.toString():
      case AndroidPromptErrorCode.ERROR_NO_DEVICE_CREDENTIAL.toString():
      case AndroidPromptErrorCode.ERROR_NO_SPACE.toString():
      case AndroidPromptErrorCode.ERROR_SECURITY_UPDATE_REQUIRED.toString():
      case AndroidPromptErrorCode.ERROR_TIMEOUT.toString():
      case AndroidPromptErrorCode.ERROR_UNABLE_TO_PROCESS.toString():
      case AndroidPromptErrorCode.ERROR_VENDOR.toString():
      default:
        return BiometricPromptError.GENERIC;
    }
  }
};

export const simplePrompt: (message: string) => Promise<{
  success: boolean;
  errorReason?: BiometricPromptError;
}> = async (message) => {
  try {
    const rnBiometrics = new ReactNativeBiometrics();

    const { success, error, errorCode } = await rnBiometrics.simplePrompt({
      promptMessage: message,
    });

    if (!!errorCode || !!error || !success) {
      throwBiometricError(errorCode, error);
    }

    return { success: true };
  } catch (e: any) {
    console.error(`simplePrompt ${e}`, e.code);
    return { success: false, errorReason: handlePromptErrors(e) };
  }
};

export const signaturePrompt: (
  message: string,
  payload: string
) => Promise<{
  success: boolean;
  signature?: string;
  errorReason?: BiometricPromptError;
}> = async (message, payload) => {
  try {
    const rnBiometrics = new ReactNativeBiometrics();

    const { signature, error, errorCode } = await rnBiometrics.createSignature({
      promptMessage: message,
      payload,
    });

    if (!!errorCode || !!error || !signature) {
      throwBiometricError(errorCode, error);
    }

    return { success: true, signature };
  } catch (e: any) {
    console.error(`signaturePrompt ${e}`, e.code);
    return { success: false, errorReason: handlePromptErrors(e) };
  }
};

export const createBiometricKeys = async () => {
  const rnBiometrics = new ReactNativeBiometrics();
  const { publicKey } = await rnBiometrics.createKeys();
  return publicKey;
};

export const deleteBiometricKeys = async () => {
  const rnBiometrics = new ReactNativeBiometrics();

  try {
    const { keysDeleted } = await rnBiometrics.deleteKeys();
    return keysDeleted;
  } catch (e) {
    return false;
  }
};

export const checkIfBiometricKeysExist = async () => {
  const rnBiometrics = new ReactNativeBiometrics();

  try {
    const { keysExist } = await rnBiometrics.biometricKeysExist();
    return keysExist;
  } catch (e) {
    return false;
  }
};
