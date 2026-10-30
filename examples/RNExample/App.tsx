import { createPeageClient } from '@peage/react-native'
import { useState } from 'react'
import {
  Button,
  ScrollView,
  StatusBar,
  StyleSheet,
  Text,
  TextInput,
  useColorScheme,
  View,
} from 'react-native'
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context'

// Your dev machine's LAN IP: on a physical device, `localhost` is the phone itself.
const DEFAULT_BASE_URL = 'http://192.168.1.149:3000'

function messageOf(error: unknown): string {
  if (!(error instanceof Error)) {
    return String(error)
  }
  return error.cause instanceof Error ? `${error.message}: ${error.cause.message}` : error.message
}

function App({ appVersion }: { appVersion?: string }) {
  const [baseUrl, setBaseUrl] = useState(DEFAULT_BASE_URL)
  const [draftBaseUrl, setDraftBaseUrl] = useState(DEFAULT_BASE_URL)
  const [peage, setPeage] = useState(() => createPeageClient({ baseUrl: DEFAULT_BASE_URL }))
  const [log, setLog] = useState<string[]>([])

  const isDark = useColorScheme() === 'dark'
  const theme = isDark ? darkTheme : lightTheme

  const append = (line: string) => {
    const entry = `[${new Date().toLocaleTimeString()}] ${line}`
    console.log(entry)
    setLog((previousLog) => [...previousLog, entry])
  }

  const onSubmitBaseUrl = () => {
    try {
      setPeage(createPeageClient({ baseUrl: draftBaseUrl }))
      setBaseUrl(draftBaseUrl)
      append(`baseUrl set to ${draftBaseUrl}`)
    } catch (error) {
      if (!(error instanceof TypeError)) {
        throw error
      }
      append(`baseUrl FAIL: ${messageOf(error)}`)
    }
  }

  const onAttest = async () => {
    append('register…')
    try {
      const keyId = await peage.register()
      append(`register OK (${keyId.slice(0, 8)}…)`)
    } catch (error) {
      append(`register FAIL: ${messageOf(error)}`)
    }
  }

  const onReset = async () => {
    append('reset…')
    try {
      await peage.clearKey()
      append('reset OK (the next request registers a new key)')
    } catch (error) {
      append(`reset FAIL: ${messageOf(error)}`)
    }
  }

  const onCallProtected = async () => {
    append('GET /api/hello …')
    try {
      const response = await peage.fetch('/api/hello')
      const text = await response.text()
      append(`→ ${response.status} ${text}`)
    } catch (error) {
      append(`request FAIL: ${messageOf(error)}`)
    }
  }

  const onCallGzip = async () => {
    append('POST /api/echo (gzip) …')
    try {
      const response = await peage.fetch('/api/echo', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'content-encoding': 'gzip' },
        body: JSON.stringify({ hello: 'gzip' }),
      })
      const text = await response.text()
      append(`→ ${response.status} ${text}`)
    } catch (error) {
      append(`request FAIL: ${messageOf(error)}`)
    }
  }

  // Same route without Péage headers: the server should answer 401.
  const onCallUnsigned = async () => {
    append('GET /api/hello (unsigned) …')
    try {
      const response = await fetch(`${baseUrl}/api/hello`)
      const text = await response.text()
      append(`→ ${response.status} ${text}`)
    } catch (error) {
      append(`request FAIL: ${messageOf(error)}`)
    }
  }

  return (
    <SafeAreaProvider>
      <SafeAreaView
        style={[styles.container, { backgroundColor: theme.background }]}
        edges={['top', 'left', 'right', 'bottom']}
      >
        <StatusBar barStyle={isDark ? 'light-content' : 'dark-content'} />
        <Text style={[styles.title, { color: theme.text }]}>Péage RN Example</Text>
        <Text style={[styles.version, { color: theme.muted }]}>{appVersion}</Text>
        <TextInput
          style={[styles.input, { color: theme.text, borderColor: theme.border }]}
          value={draftBaseUrl}
          onChangeText={setDraftBaseUrl}
          onSubmitEditing={onSubmitBaseUrl}
          returnKeyType="done"
          autoCapitalize="none"
          autoCorrect={false}
          keyboardType="url"
        />
        <View style={styles.row}>
          <Button title="Attest" onPress={onAttest} />
          <Button title="Call /api/hello" onPress={onCallProtected} />
          <Button title="Call gzip" onPress={onCallGzip} />
          <Button title="Call unsigned" onPress={onCallUnsigned} />
          <Button title="Reset" onPress={onReset} color="#cc0000" />
        </View>
        <ScrollView style={styles.log} contentContainerStyle={styles.logContent}>
          {log.map((entry, index) => (
            <Text key={index} style={[styles.logLine, { color: theme.text }]}>
              {entry}
            </Text>
          ))}
        </ScrollView>
      </SafeAreaView>
    </SafeAreaProvider>
  )
}

const lightTheme = {
  background: '#ffffff',
  text: '#000000',
  border: '#888888',
  muted: '#666666',
}

const darkTheme = {
  background: '#000000',
  text: '#ffffff',
  border: '#666666',
  muted: '#999999',
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 16, gap: 12 },
  title: { fontSize: 20, fontWeight: '600' },
  version: { fontSize: 12 },
  input: { borderWidth: 1, padding: 8, borderRadius: 4 },
  row: { flexDirection: 'row', flexWrap: 'wrap', gap: 12 },
  log: { flex: 1, marginTop: 8 },
  logContent: { paddingBottom: 16 },
  logLine: { fontFamily: 'Menlo', fontSize: 11, marginBottom: 2 },
})

export default App
