const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// Function to hash password and check against HIBP
async function isPasswordPwned(password) {
  // Generate SHA-1 hash of the password
  const hash = crypto
    .createHash('sha1')
    .update(password)
    .digest('hex')
    .toUpperCase();
  
  // Extract first 5 characters for k-anonymity
  const prefix = hash.substring(0, 5);
  const suffix = hash.substring(5);
  
  try {
    // Query HIBP API with the prefix
    const response = await fetch(
      `https://api.pwnedpasswords.com/range/${prefix}`,
      {
        headers: {
          'User-Agent': 'Asgardeo-Password-Breach-Checker'
        }
      }
    );
    
    if (!response.ok) {
      throw new Error(`HIBP API returned status ${response.status}`);
    }
    
    const data = await response.text();
    
    // Check if our hash suffix appears in the response
    const hashes = data.split('\n');
    for (const line of hashes) {
      const [hashSuffix, count] = line.split(':');
      if (hashSuffix === suffix) {
        return {
          isPwned: true,
          breachCount: parseInt(count)
        };
      }
    }
    
    return { isPwned: false, breachCount: 0 };
  } catch (error) {
    console.error('Error checking HIBP:', error);
    // In case of API failure, allow the password (fail open)
    return { isPwned: false, breachCount: 0 };
  }
}

// Pre-Update Password Action endpoint
app.post('/check-password', async (req, res) => {
  try {
    const { event, user, password } = req.body;
    
    // Validate the request
    if (!password || !password.newPassword) {
      return res.status(400).json({
        actionStatus: 'FAILED',
        message: 'Invalid request format'
      });
    }
    
    // Check if password has been pwned
    const result = await isPasswordPwned(password.newPassword);
    
    if (result.isPwned) {
      return res.json({
        actionStatus: 'FAILED',
        message: `This password has appeared in ${result.breachCount.toLocaleString()} data breaches. Please choose a different password.`,
        failureReason: 'PASSWORD_COMPROMISED'
      });
    }
    
    // Password is safe
    return res.json({
      actionStatus: 'SUCCESS'
    });
    
  } catch (error) {
    console.error('Error processing request:', error);
    return res.status(500).json({
      actionStatus: 'FAILED',
      message: 'An error occurred while validating the password'
    });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'healthy' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Password breach checker service running on port ${PORT}`);
});
