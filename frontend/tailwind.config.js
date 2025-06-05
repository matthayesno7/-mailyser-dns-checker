/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
    "./public/index.html"
  ],
  theme: {
    extend: {
      colors: {
        'mailyser-blue': '#4A90E2',
        'mailyser-green': '#50E3C2',
        'mailyser-orange': '#F5A623',
      }
    },
  },
  plugins: [],
}