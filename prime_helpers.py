# Copyright (C) 2016 Joxean Koret
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Functions in this file are taken from Cosa Nostra by Joxean Koret:
# https://github.com/joxeankoret/cosa-nostra

import os
import gc
import sys
import string
import random
import decimal


#-----------------------------------------------------------------------
def primesbelow(N):
  # http://stackoverflow.com/questions/2068372/fastest-way-to-list-all-primes-below-n-in-python/3035188#3035188
  #""" Input N>=6, Returns a list of primes, 2 <= p < N """
  correction = N % 6 > 1
  N = {0:N, 1:N-1, 2:N+4, 3:N+3, 4:N+2, 5:N+1}[N%6]
  sieve = [True] * (N // 3)
  sieve[0] = False
  for i in range(int(N ** .5) // 3 + 1):
    if sieve[i]:
      k = (3 * i + 1) | 1
      sieve[k*k // 3::2*k] = [False] * ((N//6 - (k*k)//6 - 1)//k + 1)
      sieve[(k*k + 4*k - 2*k*(i%2)) // 3::2*k] = [False] * ((N // 6 - (k*k + 4*k - 2*k*(i%2))//6 - 1) // k + 1)
  return [2, 3] + [(3 * i + 1) | 1 for i in range(1, N//3 - correction) if sieve[i]]

#-----------------------------------------------------------------------
smallprimeset = set(primesbelow(100000))
_smallprimeset = 100000
def isprime(n, precision=7):
  # http://en.wikipedia.org/wiki/Miller-Rabin_primality_test#Algorithm_and_running_time
  if n == 1 or n % 2 == 0:
    return False
  elif n < 1:
    raise ValueError("Out of bounds, first argument must be > 0")
  elif n < _smallprimeset:
    return n in smallprimeset


  d = n - 1
  s = 0
  while d % 2 == 0:
    d //= 2
    s += 1

  for repeat in range(precision):
    a = random.randrange(2, n - 2)
    x = pow(a, d, n)

    if x == 1 or x == n - 1: continue

    for r in range(s - 1):
      x = pow(x, 2, n)
      if x == 1: return False
      if x == n - 1: break
    else: return False

  return True

#-----------------------------------------------------------------------
# https://comeoncodeon.wordpress.com/2010/09/18/pollard-rho-brent-integer-factorization/
def pollard_brent(n):
  if n % 2 == 0: return 2
  if n % 3 == 0: return 3

  y, c, m = random.randint(1, n-1), random.randint(1, n-1), random.randint(1, n-1)
  g, r, q = 1, 1, 1
  while g == 1:
    x = y
    for i in range(r):
      y = (pow(y, 2, n) + c) % n

    k = 0
    while k < r and g==1:
      ys = y
      for i in range(min(m, r-k)):
        y = (pow(y, 2, n) + c) % n
        q = q * abs(x-y) % n
      g = gcd(q, n)
      k += m
    r *= 2
  if g == n:
    while True:
      ys = (pow(ys, 2, n) + c) % n
      g = gcd(abs(x - ys), n)
      if g > 1:
        break

  return g

#-----------------------------------------------------------------------
# might seem low, but 1000*1000 = 1000000, so this will fully factor
# every composite < 1000000
smallprimes = primesbelow(1000)
def primefactors(n, sort=False):
  factors = []

  limit = int(n ** decimal.Decimal(.5)) + 1
  for checker in smallprimes:
    if checker > limit: break
    while n % checker == 0:
      factors.append(checker)
      n //= checker
      limit = int(n ** decimal.Decimal(.5)) + 1
      if checker > limit: break

  if n < 2: return factors

  while n > 1:
    if isprime(n):
      factors.append(n)
      break
    factor = pollard_brent(n) # trial division did not fully factor, switch to pollard-brent
    factors.extend(primefactors(factor)) # recurse to factor the not necessarily prime factor returned by pollard-brent
    n //= factor

  if sort: factors.sort()

  return factors

#-----------------------------------------------------------------------
def factorization(n):
  factors = {}
  for p1 in primefactors(n):
    try:
      factors[p1] += 1
    except KeyError:
      factors[p1] = 1
  return factors

#-----------------------------------------------------------------------
totients = {}
def totient(n):
  if n == 0: return 1

  try: return totients[n]
  except KeyError: pass

  tot = 1
  for p, exp in factorization(n).items():
    tot *= (p - 1)  *  p ** (exp - 1)

  totients[n] = tot
  return tot

#-----------------------------------------------------------------------
def gcd(a, b):
  if a == b: return a
  while b > 0: a, b = b, a % b
  return a

#-----------------------------------------------------------------------
def lcm(a, b):
  return abs(a * b) // gcd(a, b)

#-----------------------------------------------------------------------
FACTORS_CACHE = {}
def difference(num1, num2):
  """ Calculate the difference in prime numbers. If a primer number does not 
      exists in one group but does in the other, the total value of the prime
      number is added as differences. If a primer number exists in both groups
      the values difference is added. """
  nums = [num1,
          num2]
  s = []
  for num in nums:
    if num in FACTORS_CACHE.keys():
      x = FACTORS_CACHE[num]
    else:
      x = factorization(int(num))
      FACTORS_CACHE[num] = x
    s.append(x)

  diffs = {}
  for x in s[0].keys(): # XXX: FIXME: Do not calculate again and again!
    if x in s[1].keys(): # XXX: FIXME: Do not calculate again and again!
      if s[0][x] != s[1][x]:
        diffs[x] = max(s[0][x], s[1][x]) - min(s[0][x], s[1][x])
    else:
      diffs[x] = s[0][x]
  
  for x in s[1].keys(): # XXX: FIXME: Do not calculate again and again!
    if x in s[0].keys(): # XXX: FIXME: Do not calculate again and again!
      if s[1][x] != s[0][x]:
        diffs[x] = max(s[0][x], s[1][x]) - min(s[0][x], s[1][x])
    else:
      diffs[x] = s[1][x]

  ret = sum(diffs.values())
  return ret
