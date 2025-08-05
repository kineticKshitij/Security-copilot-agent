#!/usr/bin/env python3
"""
Test database connection for Security Copilot Agent
"""

import sys
import os
sys.path.insert(0, 'src')

try:
    from security_copilot.config import config
    from security_copilot.database import DatabaseManager
    
    print("🧪 Testing Database Connection")
    print("=" * 40)
    
    # Test configuration
    print(f"📋 Configuration:")
    print(f"   Server: {config.azure_sql_server}")
    print(f"   Database: {config.azure_sql_database}")
    print(f"   Username: {config.azure_sql_username}")
    print(f"   Password: {'✅ Set' if config.azure_sql_password else '❌ Missing'}")
    print()
    
    # Test database manager initialization
    print("🔗 Initializing Database Manager...")
    db_manager = DatabaseManager()
    
    if db_manager.engine:
        print("✅ Database engine created successfully!")
        
        # Test connection
        print("🔌 Testing connection...")
        try:
            from sqlalchemy import text
            with db_manager.engine.connect() as connection:
                result = connection.execute(text("SELECT 1 AS test_value"))
                test_value = result.scalar()
                if test_value == 1:
                    print("✅ Database connection successful!")
                    print("✅ Database is ready for audit logging!")
                else:
                    print("❌ Unexpected test result")
        except Exception as e:
            print(f"❌ Connection test failed: {e}")
            
    else:
        print("❌ Database engine not created")
        
except Exception as e:
    print(f"❌ Error during testing: {e}")
    import traceback
    traceback.print_exc()
