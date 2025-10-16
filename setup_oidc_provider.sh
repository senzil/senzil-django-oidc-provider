#!/bin/bash
# Complete OIDC Provider Setup Script
# This script sets up the modernized OIDC provider with all features

set -e  # Exit on error

echo "🚀 OIDC Provider Modernization Setup"
echo "======================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check Python version
echo "📋 Checking Python version..."
python_version=$(python3 --version 2>&1 | grep -oP '\d+\.\d+' | head -1)
if [ $(echo "$python_version < 3.8" | bc) -eq 1 ]; then
    echo -e "${RED}❌ Python 3.8+ required. Found: $python_version${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Python $python_version${NC}"

# Check if virtual environment is active
if [ -z "$VIRTUAL_ENV" ]; then
    echo -e "${YELLOW}⚠️  Warning: No virtual environment detected${NC}"
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Install dependencies
echo ""
echo "📦 Installing dependencies..."
pip install -q --upgrade pip
pip install -q -r requirements.txt
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Dependencies installed${NC}"
else
    echo -e "${RED}❌ Failed to install dependencies${NC}"
    exit 1
fi

# Run migrations
echo ""
echo "🗄️  Running database migrations..."
python manage.py migrate oidc_provider
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Migrations completed${NC}"
else
    echo -e "${RED}❌ Migration failed${NC}"
    exit 1
fi

# Generate keys
echo ""
echo "🔑 Generating cryptographic keys..."

# Check if keys already exist
rsa_count=$(python manage.py shell -c "from oidc_provider.models import RSAKey; print(RSAKey.objects.count())" 2>/dev/null || echo "0")

if [ "$rsa_count" == "0" ]; then
    echo "  Generating RSA key..."
    python manage.py creatersakey
    echo -e "${GREEN}  ✅ RSA key created${NC}"
else
    echo -e "${YELLOW}  ⚠️  RSA keys already exist (count: $rsa_count)${NC}"
fi

# Generate EC keys
ec_count=$(python manage.py shell -c "from oidc_provider.models import ECKey; print(ECKey.objects.count())" 2>/dev/null || echo "0")

if [ "$ec_count" == "0" ]; then
    echo "  Generating EC keys..."
    python manage.py createeckey --curve P-256
    python manage.py createeckey --curve P-384
    python manage.py createeckey --curve P-521
    echo -e "${GREEN}  ✅ EC keys created${NC}"
else
    echo -e "${YELLOW}  ⚠️  EC keys already exist (count: $ec_count)${NC}"
fi

# Run tests
echo ""
read -p "🧪 Run test suite? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Running tests..."
    python manage.py test oidc_provider.tests.test_all_flows
    python manage.py test oidc_provider.tests.test_passkey
    python manage.py test oidc_provider.tests.test_origin_validation
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ All tests passed${NC}"
    else
        echo -e "${YELLOW}⚠️  Some tests failed${NC}"
    fi
fi

# Summary
echo ""
echo "======================================"
echo "✅ Setup Complete!"
echo "======================================"
echo ""
echo "📚 Next Steps:"
echo "  1. Configure settings.py (see UPGRADE_GUIDE.md)"
echo "  2. Set WEBAUTHN_RP_ID, RP_NAME, RP_ORIGIN"
echo "  3. Enable security middleware"
echo "  4. Create OIDC clients in Django admin"
echo "  5. Configure allowed origins for each client"
echo "  6. Test authentication flows"
echo ""
echo "📖 Documentation:"
echo "  - README_MODERNIZATION.md - Start here"
echo "  - UPGRADE_GUIDE.md - Detailed setup"
echo "  - PASSKEY_IMPLEMENTATION_GUIDE.md - Passkey setup"
echo "  - ALLOWED_DOMAINS_GUIDE.md - Origin security"
echo "  - MASTER_IMPLEMENTATION_SUMMARY.md - Complete reference"
echo ""
echo "🔐 Features Available:"
echo "  ✅ Modern JWT algorithms (ES256, PS256, etc.)"
echo "  ✅ Token encryption (JWE)"
echo "  ✅ Passkeys (WebAuthn/FIDO2)"
echo "  ✅ Origin validation"
echo "  ✅ Refresh token rotation"
echo "  ✅ Beautiful consent UI"
echo "  ✅ All OIDC flows"
echo ""
echo "🎊 Your OIDC provider is ready!"
