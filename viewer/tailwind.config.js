/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
      colors: {
        // Mantis brand — borrowed from the landing page accent palette.
        accent: {
          DEFAULT: "#7df9a4",
          hi: "#a8ffc7",
          lo: "#4ac57c",
        },
        ink: {
          900: "#0a0e0c",
          800: "#11171a",
          700: "#1a2125",
          600: "#252e34",
          500: "#3a4750",
        },
      },
    },
  },
  plugins: [],
};
