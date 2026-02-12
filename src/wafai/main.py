#!/usr/bin/env python3
"""
WAFAI Main Entry Point
"""

import sys
import argparse
from .app import Application
from .models.request import Request


def main():
    """Main entry point for WAFAI application"""
    parser = argparse.ArgumentParser(description='WAFAI - Web Application Firewall with AI')
    parser.add_argument('--config', '-c', help='Path to configuration file')
    parser.add_argument('--demo', action='store_true', help='Run demo mode')
    
    args = parser.parse_args()
    
    try:
        # Initialize application
        app = Application(config_path=args.config)
        app.start()
        
        if args.demo:
            run_demo(app)
        
        app.stop()
        return 0
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def run_demo(app: Application):
    """Run demonstration mode"""
    print("\n" + "=" * 50)
    print("DEMO MODE: Testing WAF capabilities")
    print("=" * 50)
    
    controller = app.get_controller()
    
    # Test cases
    test_requests = [
        {
            'name': 'Normal Request',
            'request': Request(
                method='GET',
                path='/api/users',
                ip_address='192.168.1.100'
            )
        },
        {
            'name': 'SQL Injection Attempt',
            'request': Request(
                method='GET',
                path='/api/users?id=1 UNION SELECT * FROM passwords',
                ip_address='10.0.0.50'
            )
        },
        {
            'name': 'XSS Attempt',
            'request': Request(
                method='POST',
                path='/api/comment',
                body='<script>alert("XSS")</script>',
                ip_address='172.16.0.10'
            )
        },
        {
            'name': 'Path Traversal Attempt',
            'request': Request(
                method='GET',
                path='/api/file?path=../../../etc/passwd',
                ip_address='203.0.113.45'
            )
        },
    ]
    
    for i, test in enumerate(test_requests, 1):
        print(f"\n--- Test {i}: {test['name']} ---")
        print(f"Request: {test['request'].method} {test['request'].path}")
        
        result = controller.process_request(test['request'])
        
        print(f"Status: {'✓ ALLOWED' if result['allowed'] else '✗ BLOCKED'}")
        
        if not result['allowed']:
            analysis = result['analysis']
            print(f"Threat Type: {analysis['threat_type']}")
            print(f"Confidence: {analysis['confidence']:.2%}")
            print(f"Rules Matched: {', '.join(analysis['rules_matched'])}")
    
    print("\n" + "=" * 50)


if __name__ == '__main__':
    sys.exit(main())
