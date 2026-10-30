// Hermes provides these as engine globals, but React Native's types don't declare them.
declare function btoa(data: string): string
declare function atob(data: string): string

declare class TextEncoder {
  readonly encoding: string
  encode(input?: string): Uint8Array
}
