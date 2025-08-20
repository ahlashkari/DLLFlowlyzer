# CSV Batch Configuration Guide

This guide explains how to configure the CSV batch writing feature in DLL Flowlyzer for optimal memory usage and performance.

## Overview

DLL Flowlyzer now supports two separate batch configurations:

1. **Processing Batch Size** (`--batch-size`): Controls memory cleanup frequency
2. **CSV Batch Size** (`--csv-batch-size`): Controls how many flows are written to CSV files at once

## Parameters

### --csv-batch-size N (Default: 30)

Controls the number of flows written to CSV files in each batch operation.

**Effects:**
- **Smaller values** (5-15): More frequent CSV updates, better for real-time monitoring, lower memory usage
- **Larger values** (50-100): Better I/O performance, fewer disk operations, higher memory usage

**Use Cases:**
- **Real-time analysis**: Use small values (5-10) for frequent updates
- **Batch processing**: Use larger values (40-60) for better performance
- **Memory-constrained systems**: Use very small values (5-8)

### --batch-size N (Default: 30)

Controls when memory cleanup operations occur (packet data clearing, garbage collection).

**Relationship with CSV Batch Size:**
- Can be the same, smaller, or larger than `--csv-batch-size`
- Independent control allows fine-tuning of memory vs. I/O performance

## Configuration Examples

### Real-Time Analysis
```bash
# Frequent CSV updates for real-time monitoring
python -m src.flowlyzer.main -i Input/ --multi-folder \
  --csv-batch-size 10 --batch-size 20
```

### High-Performance Processing
```bash
# Larger batches for better performance
python -m src.flowlyzer.main -i Input/ --multi-folder \
  --csv-batch-size 60 --batch-size 40 --workers 8
```

### Memory-Constrained Systems
```bash
# Very frequent updates with minimal memory usage
python -m src.flowlyzer.main -i Input/ --multi-folder \
  --csv-batch-size 5 --batch-size 8 --workers 1 --max-flows 1000
```

### Balanced Configuration
```bash
# Default balanced approach
python -m src.flowlyzer.main -i Input/ --multi-folder \
  --csv-batch-size 30 --batch-size 30
```

## Memory vs. Performance Trade-offs

### Small CSV Batch Size (5-15 flows)
**Advantages:**
- Lower memory usage
- More frequent CSV updates
- Better for real-time analysis
- Reduced risk of data loss

**Disadvantages:**
- More I/O operations
- Slightly lower performance
- More frequent disk writes

### Large CSV Batch Size (50-100 flows)
**Advantages:**
- Better I/O performance
- Fewer disk operations
- Better for batch processing

**Disadvantages:**
- Higher memory usage
- Less frequent updates
- More flows lost if process interrupted

## Recommended Configurations

### Small Datasets (< 100MB PCAP files)
```bash
--csv-batch-size 20 --batch-size 25 --disable-batching  # For very small files
```

### Medium Datasets (100MB - 1GB PCAP files)
```bash
--csv-batch-size 30 --batch-size 30  # Default balanced approach
```

### Large Datasets (> 1GB PCAP files)
```bash
--csv-batch-size 25 --batch-size 20 --workers 4  # Conservative memory usage
```

### Very Large Datasets (> 10GB PCAP files)
```bash
--csv-batch-size 15 --batch-size 12 --workers 2 --max-flows 5000  # Aggressive memory management
```

### Multi-Folder Processing
```bash
# For multiple large folders
--csv-batch-size 20 --batch-size 18 --folder-threads 1 --workers 4
```

## Monitoring and Tuning

### Debug Mode
Enable debug logging to monitor batch operations:
```bash
python -m src.flowlyzer.main -i Input/ --log-level DEBUG \
  --csv-batch-size 25 --batch-size 30
```

### Memory Monitoring
The system automatically monitors memory usage and provides suggestions. Look for messages like:
```
Memory estimate: 256.1 MB, Active flows: 1250, Completed flows: 30
Memory optimization suggestions:
  - Consider reducing --csv-batch-size parameter
  - Use smaller --batch-size for more frequent CSV exports
```

## Best Practices

1. **Start with defaults** (30/30) and adjust based on performance
2. **Monitor memory usage** with debug logging
3. **Use smaller CSV batches** for memory-constrained systems
4. **Use larger CSV batches** for high-performance requirements
5. **Keep batch-size <= csv-batch-size** for optimal memory management
6. **Test different configurations** with your specific data

## Troubleshooting

### High Memory Usage
- Reduce `--csv-batch-size` to 15 or lower
- Reduce `--batch-size` to 20 or lower
- Use `--workers 1` or `--workers 2`

### Slow Performance
- Increase `--csv-batch-size` to 40-60
- Increase `--batch-size` to 40-50
- Use more workers if memory allows

### Frequent I/O Operations
- Increase `--csv-batch-size` to reduce disk writes
- Monitor disk usage during processing

This configuration system provides fine-grained control over the balance between memory usage, performance, and CSV update frequency.