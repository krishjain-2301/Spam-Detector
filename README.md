# 🛡️ Spam Detector Pro

A powerful desktop application for real-time spam detection using AI technology. Built with Electron and Google Gemini AI.

## ✨ Features

- **🔄 Clipboard Monitoring**: Automatically detects suspicious content when you copy emails, links, or phone numbers
- **🤖 AI-Powered Detection**: Uses Google Gemini AI to analyze content for spam patterns and phishing attempts
- **📁 File Scanning**: Drag & drop .txt and .eml files for instant analysis
- **⚡ Real-time Validation**: Get instant feedback as you type with color-coded validation
- **🔔 Smart Notifications**: Instant popup warnings for suspicious content
- **🎯 System Tray Integration**: Runs quietly in the background for continuous protection

## 🚀 Quick Start

### 1. Install Dependencies

```bash
npm install
```

### 2. Get Your Gemini API Key

1. Visit [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Create a new API key
3. Copy the API key

### 3. Configure the App

Set your Gemini API key as an environment variable:

**Windows:**
```cmd
set GEMINI_API_KEY=your_api_key_here
```

**macOS/Linux:**
```bash
export GEMINI_API_KEY=your_api_key_here
```

### 4. Start the App

```bash
npm start
```

## 🎯 How to Use

### Clipboard Monitoring
- The app automatically starts monitoring your clipboard
- When you copy suspicious content, you'll get instant notifications
- Toggle monitoring on/off using the system tray or main window

### File Scanning
- Drag and drop .txt or .eml files into the drop zone
- Or click "Browse Files" to select files manually
- Get instant spam analysis results

### Live Input Validation
- Type emails, phone numbers, URLs, or any text in the input fields
- Get real-time validation with color-coded feedback:
  - 🟢 Green: Safe content
  - 🟡 Yellow: Warning (medium risk)
  - 🔴 Red: Danger (high risk)

### System Tray
- Right-click the tray icon to access controls
- Start/stop monitoring
- Show/hide the main window
- Quit the application

## 🔧 Configuration

The app uses several detection methods:

1. **AI Analysis**: Google Gemini AI analyzes content for spam patterns
2. **Pattern Matching**: Regex patterns for emails, phone numbers, URLs
3. **Keyword Detection**: Identifies suspicious keywords and phrases
4. **Context Analysis**: Considers surrounding text for better accuracy

## 📁 Project Structure

```
src/
├── main.js          # Main Electron process
├── renderer.js      # Renderer process (UI logic)
├── preload.js       # Secure IPC bridge
└── index.css        # Modern UI styling

assets/              # App icons and images
index.html           # Main HTML structure
package.json         # Dependencies and scripts
```

## 🛠️ Development

### Building for Production

```bash
npm run make
```

### Packaging

```bash
npm run package
```

## 🔒 Security Features

- **Context Isolation**: Secure IPC communication between processes
- **No Node Integration**: Renderer process runs in secure sandbox
- **API Key Protection**: Environment variable configuration
- **File Validation**: Only processes supported file types

## 📊 Detection Capabilities

The app can detect:

- **Phishing Emails**: Suspicious email patterns and content
- **Malicious URLs**: Dangerous links and shortened URLs
- **Spam Phone Numbers**: Suspicious phone number patterns
- **Social Engineering**: Manipulative language and tactics
- **Suspicious Keywords**: Common spam terminology
- **Context Patterns**: Unusual combinations of elements

## 🎨 UI Features

- **Modern Design**: Clean, professional interface
- **Responsive Layout**: Works on different screen sizes
- **Drag & Drop**: Intuitive file handling
- **Real-time Feedback**: Instant validation results
- **Color-coded Results**: Easy-to-understand risk levels
- **Smooth Animations**: Polished user experience

## 🔧 Troubleshooting

### Common Issues

1. **API Key Not Working**
   - Ensure the environment variable is set correctly
   - Check that the API key is valid and active

2. **Clipboard Monitoring Not Working**
   - Check if monitoring is enabled in the app
   - Ensure the app has necessary permissions

3. **File Scanning Issues**
   - Only .txt and .eml files are supported
   - Check file size (max 10MB)

### Getting Help

If you encounter issues:
1. Check the console for error messages
2. Ensure all dependencies are installed
3. Verify your Gemini API key is valid

## 📄 License

MIT License - feel free to use and modify as needed.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

---

**Built with ❤️ using Electron and Google Gemini AI**
