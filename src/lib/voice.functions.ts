import { createServerFn } from "@tanstack/react-start";

export type VoiceBriefInput = { text: string; voiceId?: string };

export const speakBriefing = createServerFn({ method: "POST" })
  .inputValidator((d: VoiceBriefInput) => d)
  .handler(async ({ data }) => {
    const apiKey = process.env["ELEVENLABS_API_KEY"];
    if (!apiKey) throw new Error("ElevenLabs is not connected to this project");

    const voiceId = data.voiceId || "JBFqnCBsd6RMkjVDRZzb"; // George
    const text = data.text.slice(0, 4800);

    const response = await fetch(
      `https://api.elevenlabs.io/v1/text-to-speech/${voiceId}?output_format=mp3_44100_128`,
      {
        method: "POST",
        headers: { "xi-api-key": apiKey, "Content-Type": "application/json" },
        body: JSON.stringify({
          text,
          model_id: "eleven_multilingual_v2",
          voice_settings: {
            stability: 0.6,
            similarity_boost: 0.75,
            style: 0.3,
            use_speaker_boost: true,
            speed: 1.0,
          },
        }),
      },
    );

    if (!response.ok) {
      const body = await response.text();
      console.error(`ElevenLabs TTS failed [${response.status}]: ${body}`);
      throw new Error(`ElevenLabs TTS failed [${response.status}]: ${body}`);
    }

    const bytes = new Uint8Array(await response.arrayBuffer());
    let bin = "";
    for (let i = 0; i < bytes.length; i += 0x8000) {
      bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    }
    return {
      audioContent: btoa(bin),
      chars: text.length,
    };
  });
