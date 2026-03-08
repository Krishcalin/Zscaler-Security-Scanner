# Contributing
## Adding Checks
1. Add check_* method to appropriate auditor in modules/
2. Register in zscaler_scanner.py MODULE_MAP if new module
3. Add sample data in generate_sample_data section
4. Test: python zscaler_scanner.py --data-dir ./sample_data
5. Update README
