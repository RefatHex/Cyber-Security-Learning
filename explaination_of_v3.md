# Mathematical Example - Line by Line

**real numbers** to see exactly what's happening.

---

## **Scenario: 1 Second of Network Traffic**

Imagine 5 different IPs sent packets. Here's what we counted:

| IP           | Packets Sent | Rate (packets/sec)   |
| ------------ | ------------ | -------------------- |
| 192.168.1.10 | 8            | 8 pps                |
| 192.168.1.20 | 10           | 10 pps               |
| 192.168.1.30 | 9            | 9 pps                |
| 192.168.1.40 | 7            | 7 pps                |
| 192.168.1.50 | 150          | 150 pps ⚠️ (ATTACK!) |

---

## **Step 1: Calculate Mean**

```python
rates = [8, 10, 9, 7, 150]
mean_rate = statistics.mean(rates)
```

**Math:**

```
mean_rate = (8 + 10 + 9 + 7 + 150) / 5
mean_rate = 184 / 5
mean_rate = 36.8 pps
```

✅ **Average packets per second = 36.8**

---

## **Step 2: Calculate Standard Deviation**

```python
stdev = statistics.stdev(rates)
```

**Math (simplified):**

```
stdev measures how spread out the numbers are.

Distance from mean for each IP:
- 192.168.1.10: |8 - 36.8| = 28.8
- 192.168.1.20: |10 - 36.8| = 26.8
- 192.168.1.30: |9 - 36.8| = 27.8
- 192.168.1.40: |7 - 36.8| = 29.8
- 192.168.1.50: |150 - 36.8| = 113.2

stdev ≈ 61.5 pps
```

✅ **Standard deviation = 61.5**

---

## **Step 3: Check the Condition**

```python
if (rate > mean_rate + (3 * stdev)) and ip not in blocked_ips:
```

**Translate to numbers:**

```
threshold = mean_rate + (3 * stdev)
threshold = 36.8 + (3 × 61.5)
threshold = 36.8 + 184.5
threshold = 221.3 pps
```

Now check **each IP**:

| IP           | Rate | > 221.3? | Block? |
| ------------ | ---- | -------- | ------ |
| 192.168.1.10 | 8    | ❌ No    | No     |
| 192.168.1.20 | 10   | ❌ No    | No     |
| 192.168.1.30 | 9    | ❌ No    | No     |
| 192.168.1.40 | 7    | ❌ No    | No     |
| 192.168.1.50 | 150  | ❌ No    | No     |

---

## **Wait! Why Didn't We Block 192.168.1.50?**

Because **150 < 221.3**, so it didn't trigger the block.

The threshold was **too high** because the attacker (150 pps) wasn't extreme enough compared to the standard deviation.

---

## **Real Attack Scenario**

Let's make it more realistic:

| IP           | Packets | Rate                    |
| ------------ | ------- | ----------------------- |
| 192.168.1.10 | 8       | 8 pps                   |
| 192.168.1.20 | 10      | 10 pps                  |
| 192.168.1.30 | 9       | 9 pps                   |
| 192.168.1.40 | 7       | 7 pps                   |
| 192.168.1.50 | 5000    | 5000 pps ⚠️ REAL ATTACK |

**New calculation:**

```
mean_rate = (8 + 10 + 9 + 7 + 5000) / 5 = 1006.8 pps
stdev ≈ 2235 pps

threshold = 1006.8 + (3 × 2235)
threshold = 1006.8 + 6705
threshold = 7711.8 pps
```

Check IP 192.168.1.50:

```
rate = 5000
5000 > 7711.8? ❌ Still NO!
```

This is a **weakness** of the algorithm when there's only one attacker among few IPs.

---

## **Better Example: More Background Traffic**

```
Normal IPs: 8, 9, 7, 10, 8, 9, 7, 8, 9, 10 pps (normal background)
Attacker: 500 pps

mean_rate = (8+9+7+10+8+9+7+8+9+10+500) / 11 ≈ 57.6 pps
stdev ≈ 151.2 pps

threshold = 57.6 + (3 × 151.2)
threshold = 57.6 + 453.6
threshold = 511.2 pps
```

Check attacker:

```
rate = 500
500 > 511.2? ❌ Close, but still NO!
```

---

## **EXTREME Attack Example**

```
Normal: 8, 9, 7, 10 pps each (20 IPs)
Attacker: 10000 pps

mean ≈ 255.2 pps
stdev ≈ 2236 pps

threshold = 255.2 + (3 × 2236)
threshold = 255.2 + 6708
threshold = 6963.2 pps
```

Check attacker:

```
rate = 10000
10000 > 6963.2? ✅ YES! BLOCK IT!
```

---

## **TL;DR - The Magic Formula**

```
threshold = mean_rate + (3 × stdev)

If an IP's rate > threshold → BLOCK IT

The "3 ×" means: "Only block if this IP is 3 standard deviations
above the average" (extremely abnormal)
```
