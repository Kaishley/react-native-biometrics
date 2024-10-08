import { StyleSheet, View, Button } from 'react-native';
import {
  checkIfBiometricKeysExist,
  createBiometricKeys,
  deleteBiometricKeys,
  getBiometricSensorStatus,
  signaturePrompt,
  simplePrompt,
} from './Biometrics';

export default function App() {
  const handleIsSensorAvailable = async () => {
    const res = await getBiometricSensorStatus();
    console.log(res);
  };

  const handleSimplePrompt = async () => {
    const res = await simplePrompt('Please authenticate');
    console.log(res);
  };

  const handleSignaturePrompt = async () => {
    const res = await signaturePrompt('Please sign', 'test payload');
    console.log(res);
  };

  const handleCreateKeys = async () => {
    const res = await createBiometricKeys();
    console.log(res);
  };

  const handleDeleteKeys = async () => {
    const res = await deleteBiometricKeys();
    console.log(res);
  };

  const handleBiometricKeysExist = async () => {
    const res = await checkIfBiometricKeysExist();
    console.log(res);
  };

  return (
    <View style={styles.container}>
      <Button onPress={handleIsSensorAvailable} title="isSensorAvailable()" />
      <Button onPress={handleSimplePrompt} title="simplePrompt()" />
      <Button onPress={handleSignaturePrompt} title="createSignature()" />
      <Button onPress={handleCreateKeys} title="createKeys()" />
      <Button onPress={handleDeleteKeys} title="deleteKeys()" />
      <Button onPress={handleBiometricKeysExist} title="biometricKeysExist()" />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    gap: 20,
  },
});
