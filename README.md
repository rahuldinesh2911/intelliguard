# IntelliGuard SOC Dashboard

A real-time IoT security monitoring dashboard with threat detection and anomaly analysis.

## 🚀 GitHub Pages Deployment

This project is configured for easy deployment to GitHub Pages with simulated data generation.

### Quick Setup

1. **Fork/Clone this repository**
2. **Update the repository name in `frontend/vite.config.js`:**
   ```js
   base: process.env.NODE_ENV === 'production' ? '/your-repo-name/' : '/',
   ```
3. **Enable GitHub Pages:**
   - Go to your repository Settings
   - Navigate to Pages section
   - Set Source to "GitHub Actions"
4. **Push to main branch** - deployment will happen automatically

### Local Development

```bash
cd frontend
npm install
npm run dev
```

### Features in Demo Mode

- ✅ Random IoT device simulation
- ✅ Real-time threat detection
- ✅ Interactive charts and metrics
- ✅ Device monitoring and quarantine
- ✅ Security reports and analytics
- ✅ Responsive design

### Demo Controls

- **Start/Stop Button**: Begin/pause the simulation
- **Refresh**: Reset all data
- **Export**: Download CSV reports
- **Clear**: Reset traffic table

The demo automatically generates realistic IoT traffic patterns with occasional security threats to showcase the monitoring capabilities.

## 🛠 Technology Stack

- **Frontend**: React + Vite
- **Charts**: Chart.js
- **Styling**: Tailwind CSS
- **Icons**: Lucide React
- **Deployment**: GitHub Pages + Actions