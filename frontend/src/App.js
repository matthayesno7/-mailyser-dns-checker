import React, { useState } from "react";
import "./App.css";

// Fun images for success and error states
const SuccessImage = () => (
  <div className="w-32 h-32 rounded-full overflow-hidden shadow-lg">
    <img 
      src="https://images.pexels.com/photos/18148286/pexels-photo-18148286.jpeg" 
      alt="Success - Thumbs Up"
      className="w-full h-full object-cover"
    />
  </div>
);

const ErrorImage = () => (
  <div className="w-32 h-32 rounded-full overflow-hidden shadow-lg">
    <img 
      src="https://images.pexels.com/photos/3747139/pexels-photo-3747139.jpeg" 
      alt="Error - Technical Issue"
      className="w-full h-full object-cover"
    />
  </div>
);

const WarningImage = () => (
  <div className="w-32 h-32 rounded-full overflow-hidden shadow-lg">
    <img 
      src="https://images.pexels.com/photos/9211268/pexels-photo-9211268.jpeg" 
      alt="Warning - Needs Attention"
      className="w-full h-full object-cover"
    />
  </div>
);

const RecordCard = ({ record, type }) => {
  const getStatusColor = (status) => {
    switch (status) {
      case 'valid': return 'bg-green-50 border-green-200';
      case 'warning': return 'bg-yellow-50 border-yellow-200';
      case 'missing': 
      case 'invalid': return 'bg-red-50 border-red-200';
      default: return 'bg-gray-50 border-gray-200';
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'valid': return <span className="text-green-600">✓</span>;
      case 'warning': return <span className="text-yellow-600">⚠</span>;
      case 'missing':
      case 'invalid': return <span className="text-red-600">✗</span>;
      default: return <span className="text-gray-600">?</span>;
    }
  };

  return (
    <div className={`p-4 rounded-lg border-2 ${getStatusColor(record.status)} transition-all duration-300`}>
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-lg font-semibold text-gray-800 flex items-center gap-2">
          {getStatusIcon(record.status)}
          {type}
        </h3>
        <span className={`px-3 py-1 rounded-full text-sm font-medium ${
          record.status === 'valid' ? 'bg-green-100 text-green-800' :
          record.status === 'warning' ? 'bg-yellow-100 text-yellow-800' :
          'bg-red-100 text-red-800'
        }`}>
          {record.status}
        </span>
      </div>
      
      {record.record && (
        <div className="mb-3">
          <p className="text-sm font-medium text-gray-600 mb-1">Record:</p>
          <code className="text-xs bg-gray-100 p-2 rounded block overflow-x-auto">
            {record.record}
          </code>
        </div>
      )}
      
      {record.issues && record.issues.length > 0 && (
        <div className="mb-3">
          <p className="text-sm font-medium text-red-600 mb-1">Issues:</p>
          <ul className="text-sm text-red-600 list-disc list-inside">
            {record.issues.map((issue, index) => (
              <li key={index}>{issue}</li>
            ))}
          </ul>
        </div>
      )}
      
      {record.recommendations && record.recommendations.length > 0 && (
        <div>
          <p className="text-sm font-medium text-blue-600 mb-1">Recommendations:</p>
          <ul className="text-sm text-blue-600 list-disc list-inside">
            {record.recommendations.map((rec, index) => (
              <li key={index}>{rec}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};

function App() {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  // DNS checking using external DNS-over-HTTPS service
  const checkDNS = async (domain, recordType) => {
    try {
      const response = await fetch(`https://dns.google/resolve?name=${domain}&type=${recordType}`);
      const data = await response.json();
      return data.Answer || [];
    } catch (err) {
      return [];
    }
  };

  const handleCheck = async (e) => {
    e.preventDefault();
    if (!email) return;

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const domain = email.split('@')[1].toLowerCase();
      
      // Check SPF record
      const txtRecords = await checkDNS(domain, 'TXT');
      const spfRecords = txtRecords.filter(record => 
        record.data.includes('v=spf1')
      );

      let spf;
      if (spfRecords.length === 0) {
        spf = {
          type: "SPF",
          status: "missing",
          record: null,
          issues: ["No SPF record found"],
          recommendations: ["Add an SPF record to your DNS", "Example: v=spf1 include:_spf.google.com ~all"]
        };
      } else {
        const spfRecord = spfRecords[0].data.replace(/"/g, '');
        const issues = [];
        const recommendations = [];
        
        if (!spfRecord.includes('~all') && !spfRecord.includes('-all')) {
          issues.push("SPF record should end with an 'all' mechanism");
          recommendations.push("Add ~all (softfail) or -all (hardfail) at the end");
        }
        
        spf = {
          type: "SPF",
          status: issues.length === 0 ? "valid" : "warning",
          record: spfRecord,
          issues,
          recommendations
        };
      }

      // Check DMARC record
      const dmarcRecords = await checkDNS(`_dmarc.${domain}`, 'TXT');
      const dmarcFound = dmarcRecords.filter(record => 
        record.data.includes('v=DMARC1')
      );

      let dmarc;
      if (dmarcFound.length === 0) {
        dmarc = {
          type: "DMARC",
          status: "missing",
          record: null,
          issues: ["No DMARC record found"],
          recommendations: ["Add a DMARC record to your DNS", "Example: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com"]
        };
      } else {
        const dmarcRecord = dmarcFound[0].data.replace(/"/g, '');
        const issues = [];
        const recommendations = [];
        
        if (dmarcRecord.includes('p=none')) {
          issues.push("DMARC policy is set to 'none' - emails won't be protected");
          recommendations.push("Consider upgrading to p=quarantine or p=reject");
        }
        
        dmarc = {
          type: "DMARC",
          status: issues.length === 0 ? "valid" : "warning",
          record: dmarcRecord,
          issues,
          recommendations
        };
      }

      // Check DKIM (simplified - just check if common selectors exist)
      const dkimSelectors = ['default', 'selector1', 'google'];
      let dkim = {
        type: "DKIM",
        status: "missing",
        record: null,
        issues: ["No DKIM records found with common selectors"],
        recommendations: ["Set up DKIM signing for your email service", "Common selectors checked: default, selector1, google"]
      };

      for (const selector of dkimSelectors) {
        const dkimRecords = await checkDNS(`${selector}._domainkey.${domain}`, 'TXT');
        if (dkimRecords.length > 0) {
          dkim = {
            type: "DKIM",
            status: "valid",
            record: `Selector: ${selector} (found)`,
            issues: [],
            recommendations: []
          };
          break;
        }
      }

      // Determine overall status
      const statuses = [spf.status, dmarc.status, dkim.status];
      const validCount = statuses.filter(s => s === 'valid').length;
      const missingCount = statuses.filter(s => s === 'missing').length;
      
      let overallStatus;
      if (validCount >= 2) {
        overallStatus = "pass";
      } else if (missingCount >= 2) {
        overallStatus = "fail";
      } else {
        overallStatus = "warning";
      }

      setResult({
        email,
        domain,
        overall_status: overallStatus,
        spf,
        dmarc,
        dkim,
        timestamp: new Date().toISOString()
      });

    } catch (err) {
      setError('An error occurred while checking DNS records. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const getOverallStatusConfig = (status) => {
    switch (status) {
      case 'pass':
        return {
          title: 'Great! Your DNS is properly configured! 🎉',
          subtitle: 'Your email authentication is set up correctly',
          bgColor: 'bg-green-50',
          borderColor: 'border-green-200',
          textColor: 'text-green-800',
          image: <SuccessImage />
        };
      case 'warning':
        return {
          title: 'Your DNS setup needs some attention ⚠️',
          subtitle: 'Some records could be improved for better email deliverability',
          bgColor: 'bg-yellow-50',
          borderColor: 'border-yellow-200',
          textColor: 'text-yellow-800',
          image: <WarningImage />
        };
      case 'fail':
        return {
          title: 'Your DNS setup has critical issues ❌',
          subtitle: 'Important email authentication records are missing or invalid',
          bgColor: 'bg-red-50',
          borderColor: 'border-red-200',
          textColor: 'text-red-800',
          image: <ErrorImage />
        };
      default:
        return {
          title: 'DNS Check Complete',
          subtitle: 'Review the results below',
          bgColor: 'bg-gray-50',
          borderColor: 'border-gray-200',
          textColor: 'text-gray-800',
          image: <div className="w-32 h-32 bg-gray-200 rounded-full"></div>
        };
    }
  };

  return (
    <div className="min-h-screen" style={{ backgroundColor: '#f8fafc' }}>
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="w-8 h-8 rounded" style={{ backgroundColor: '#4A90E2' }}></div>
              <h1 className="text-2xl font-bold text-gray-900">Mailyser DNS Checker</h1>
            </div>
            <p className="text-sm text-gray-600">Reach the inbox with confidence</p>
          </div>
        </div>
      </header>

      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Hero Section */}
        <div className="text-center mb-8">
          <h2 className="text-4xl font-bold text-gray-900 mb-4">
            Check Your Email DNS Setup
          </h2>
          <p className="text-xl text-gray-600 mb-8">
            Quickly verify your SPF, DMARC, and DKIM records to ensure perfect email deliverability
          </p>
        </div>

        {/* Input Form */}
        <div className="bg-white rounded-lg shadow-md p-6 mb-8">
          <form onSubmit={handleCheck} className="space-y-4">
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-2">
                Enter your "From" email address
              </label>
              <input
                type="email"
                id="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="newsletter@yourcompany.com"
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-lg"
                required
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 px-6 text-white font-semibold rounded-lg transition-colors duration-200 text-lg"
              style={{ backgroundColor: loading ? '#9CA3AF' : '#4A90E2' }}
            >
              {loading ? 'Checking DNS Records...' : 'Check DNS Setup'}
            </button>
          </form>
        </div>

        {/* Error Display */}
        {error && (
          <div className="bg-red-50 border-2 border-red-200 rounded-lg p-4 mb-8">
            <p className="text-red-800">{error}</p>
          </div>
        )}

        {/* Results */}
        {result && (
          <div className="space-y-6">
            {/* Overall Status */}
            <div className={`rounded-lg border-2 p-6 text-center ${getOverallStatusConfig(result.overall_status).bgColor} ${getOverallStatusConfig(result.overall_status).borderColor}`}>
              <div className="flex flex-col items-center space-y-4">
                {getOverallStatusConfig(result.overall_status).image}
                <div>
                  <h3 className={`text-2xl font-bold ${getOverallStatusConfig(result.overall_status).textColor}`}>
                    {getOverallStatusConfig(result.overall_status).title}
                  </h3>
                  <p className={`text-lg ${getOverallStatusConfig(result.overall_status).textColor} opacity-80`}>
                    {getOverallStatusConfig(result.overall_status).subtitle}
                  </p>
                  <p className="text-sm text-gray-600 mt-2">
                    Domain: <span className="font-mono">{result.domain}</span>
                  </p>
                </div>
              </div>
            </div>

            {/* Detailed Records */}
            <div className="grid md:grid-cols-3 gap-6">
              <RecordCard record={result.spf} type="SPF Record" />
              <RecordCard record={result.dmarc} type="DMARC Record" />
              <RecordCard record={result.dkim} type="DKIM Record" />
            </div>

            {/* Additional Info */}
            <div className="bg-blue-50 border-2 border-blue-200 rounded-lg p-4">
              <h4 className="font-semibold text-blue-800 mb-2">💡 Need help with DNS setup?</h4>
              <p className="text-blue-700 text-sm">
                Visit <a href="https://www.mailyser.com" className="underline font-medium">Mailyser.com</a> for comprehensive email deliverability tools and expert guidance.
              </p>
            </div>
          </div>
        )}
      </div>

      {/* Footer */}
      <footer className="bg-white border-t mt-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="text-center">
            <p className="text-gray-600">
              Free DNS Checker by{' '}
              <a href="https://www.mailyser.com" className="font-medium" style={{ color: '#4A90E2' }}>
                Mailyser
              </a>
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
