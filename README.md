# Laravel Log Parser

A powerful CLI tool for analyzing Laravel application logs with advanced filtering, remote SSH support, and comprehensive statistics.

## Features

- Parse local and remote Laravel log files
- SSH integration for remote log analysis
- Advanced filtering by level, date, user, and content
- Colorized output with multiple display formats
- Comprehensive statistics and grouping
- JSON export capabilities
- Real-time log analysis

## Installation

```bash
git clone https://github.com/nickcheek/laravel-log-parser.git
cd laravel-log-parser
go build -o parse
```

## Usage

### Basic Usage

```bash
# Parse local log file
./parse storage/logs/laravel.log

# Parse remote log via SSH
./parse stage-web

# Show only errors and warnings
./parse --errors-only production

# Display summary statistics
./parse --summary --since=2025-06-13 laravel.log
```

### Remote SSH Logs

The tool automatically detects SSH targets and connects to remote servers:

```bash
# These will trigger SSH connections
./parse production-web
./parse staging-api
./parse dev-server
```

The tool will:

1. Look up the host in your `~/.ssh/config`
2. SSH to that host and fetch the log file
3. Parse it locally with all available features

### Filtering Options

#### By Log Level

```bash
./parse --level=ERROR laravel.log
./parse --errors-only laravel.log
```

#### By Date Range

```bash
./parse --since=2025-06-13 laravel.log
./parse --until="2025-06-14 15:30" laravel.log
./parse --since="2025-06-13 09:00" --until="2025-06-13 17:00" laravel.log
```

#### By Content

```bash
./parse --search="database" laravel.log
./parse --user=123 laravel.log
```

#### Limit Results

```bash
./parse --last=50 laravel.log
```

### Display Formats

#### Compact Output

```bash
./parse --compact laravel.log
```

#### JSON Output

```bash
./parse --json laravel.log
```

#### Grouped Results

```bash
./parse --group-by=level laravel.log
./parse --group-by=message laravel.log
./parse --group-by=file laravel.log
./parse --group-by=user laravel.log
```

### Statistics and Analysis

#### Summary View

```bash
./parse --summary laravel.log
```

#### Detailed Statistics

```bash
./parse --stats laravel.log
```

## Command Line Options

| Option          | Description                                              |
| --------------- | -------------------------------------------------------- |
| `--level`       | Filter by log level (DEBUG, INFO, WARNING, ERROR)        |
| `--errors-only` | Show only errors and warnings                            |
| `--group-by`    | Group results by: message, level, file, user             |
| `--json`        | Output in JSON format                                    |
| `--summary`     | Show summary statistics                                  |
| `--since`       | Show logs since date (YYYY-MM-DD or YYYY-MM-DD HH:MM)    |
| `--until`       | Show logs until date (YYYY-MM-DD or YYYY-MM-DD HH:MM)    |
| `--search`      | Search for specific text in messages                     |
| `--user`        | Filter by user ID                                        |
| `--no-color`    | Disable colored output                                   |
| `--compact`     | Compact output format                                    |
| `--stats`       | Show detailed statistics                                 |
| `--last`        | Show last N entries                                      |
| `--remote-path` | Remote log file path (default: storage/logs/laravel.log) |
| `--ssh-config`  | Path to SSH config file (default: ~/.ssh/config)         |

## SSH Configuration

For remote log parsing, ensure your `~/.ssh/config` is properly configured:

```
Host production-web
    HostName 192.168.1.100
    User deploy
    IdentityFile ~/.ssh/production_key

Host staging-api
    HostName staging.example.com
    User ubuntu
    Port 2222
```

## Examples

### Development Workflow

```bash
# Quick error check on production
./parse --errors-only production-web

# Debug specific user issues
./parse --user=12345 --since=2025-06-13 staging-api

# Monitor database-related issues
./parse --search="database" --level=ERROR laravel.log

# Generate daily report
./parse --summary --since=2025-06-13 --until=2025-06-14 production-web
```

### Analysis and Reporting

```bash
# Top error messages
./parse --group-by=message --errors-only laravel.log

# Most active users
./parse --group-by=user --stats laravel.log

# Problem files analysis
./parse --group-by=file --stats laravel.log

# Export for external analysis
./parse --json --since=2025-06-13 laravel.log > daily-logs.json
```

## Output Format

### Standard Output

```
╭─ 2025-06-14 10:30:15 [ERROR] production
│  SQLSTATE[42S02]: Base table or view not found
│  User: 12345  Request: a1b2c3d4  File: .../QueryException.php:37
╰─
```

### Compact Output

```
10:30:15 ERROR   SQLSTATE[42S02]: Base table or view not found [user:12345] .../QueryException.php:37
```

### Summary Statistics

```
Log Analysis Summary
═══════════════════════
Total entries: 1,247
Time range: 2025-06-13 00:00 to 2025-06-14 23:59

Log Levels:
  INFO     856 (68.6%)
  ERROR    201 (16.1%)
  WARNING  142 (11.4%)
  DEBUG     48 (3.9%)

Top Issues:
  1. SQLSTATE[42S02]: Base table or view not found (45 occurrences)
  2. Call to undefined method (23 occurrences)
  3. Class 'App\Models\User' not found (18 occurrences)
```

## Log Format Support

The parser supports standard Laravel log format:

```
[2025-06-14 10:30:15] production.ERROR: Error message {"userId":123,"request_id":"abc123"}
```

## Requirements

- Go 1.19 or higher
- SSH access to remote servers (for remote log parsing)
- Properly configured SSH keys and config

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

MIT License
