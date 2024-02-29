---
title: "Leet Code Exercises"
date: 2024-01-29T20:40:03+01:00
draft: false
categories: dev
---

# Leet Code Exercises

Here is a list of my Leet Code solution (non exaustive). I am following https://neetcode.io/roadmap

## Contains Duplicate

```python
class Solution:
    def containsDuplicate(self, nums: List[int]) -> bool:
        result = {}

        for item in nums:
            if item in result:
                return True
            result[item] = True

        return False
```
## Valid Anagram

```python
class Solution:
    def isAnagram(self, s: str, t: str) -> bool:
        
        res = {}

        for item in s:
            if item in res:
                res[item]+=1
            else:
                res[item]=1

        for item in t:
            if item in res:
                res[item]-=1
                if res[item]==0:
                    del res[item]
            else:
                return False

        if len(res)>0:
            return False

        
        return True
```


## Two Sum

```python
class Solution:
    def twoSum(self, nums: List[int], target: int) -> List[int]:
        
        for i in range(len(nums)):
            for j in range(i+1,len(nums)):
                if nums[i] + nums[j] == target:

                    return [i,j]
```

## Group Anagrams

```python
class Solution:

    def groupAnagrams(self, strs: List[str]) -> List[List[str]]:
        
        res = {}

        for s in strs:
            ss = str(sorted(s))
            if ss in res:
                res[ss].append(s)
            else:
                res[ss] = [s]

        return (list(res.values()))
```

## Top K Frequent Elements

```python
class Solution:
    def topKFrequent(self, nums: List[int], k: int) -> List[int]:
        if len(nums) == 1:
            return [nums[0]]

        occ = {}

        for i in range(len(nums)):
            if nums[i] in occ:
                occ[nums[i]] += 1
            else:
                occ[nums[i]] = 1

        socc = sorted(occ.items(),key=lambda x:x[1],reverse=True)


        v = list(dict(socc).keys())
        return v[0:k]
```

O(n) with buckets


## Product of Array Except Self

```python
class Solution:
    def productExceptSelf(self, nums: List[int]) -> List[int]:
        answer = [1 for _ in range(len(nums))]

        pre = [1 for _ in range(len(nums))]
        post  = [1 for _ in range(len(nums))]

        for i in range(1,len(nums)):
            pre[i] = pre[i-1] * nums[i-1]

        for i in range(len(nums)-2,-1,-1):
            post[i] = post[i+1] * nums[i+1]

        for i in range(len(nums)):
            answer[i] = pre[i] * post[i]
            
    

        return answer
```


## Valid Sudoku

```python
class Solution:

    def isValidRow(self,board,row):

        occ = {}
        for i in range(9):
            if board[row][i] != ".":
                if board[row][i] in occ:
                    return False
                else:
                    occ[board[row][i]] = True
            

        return True

    def isValidColumn(self,board,column):

        occ = {}

        for i in range(9):
            if board[i][column] != ".":
                if board[i][column] in occ:
                    return False
                else:
                    occ[board[i][column]] = True

        return True

    def isValidBox(self,board,row,column):

        occ = {}
        for i in range(row,row+3):
            for j in range(column,column+3):
                if board[i][j] != ".":
                    if board[i][j] in occ:
                        return False
                    else:
                        occ[board[i][j]] = True          

        return True
        
    def isValidSudoku(self, board: List[List[str]]) -> bool:

        for i in range(9):
            if not self.isValidRow(board,i):
                return False
        
            if not self.isValidColumn(board,i):
                return False

        for i in range(3):
            for j in range(3):
                if not self.isValidBox(board,i*3,j*3):
                    return False


        return True
        
```

## Min Stack

```python
class MinStack:

    def __init__(self):
        self.stack = []
        self.min_stack = []

    def push(self, val: int) -> None:
        self.stack.append(val)
        if len(self.min_stack) == 0:
            self.min_stack.append(val)
        else:
            if self.min_stack[-1] >= val:
                self.min_stack.append(val)
        

    def pop(self) -> None:
        v = self.stack.pop()
        if self.min_stack[-1] == v:
            self.min_stack.pop()
        

    def top(self) -> int:
        return self.stack[-1]
        

    def getMin(self) -> int:
        return self.min_stack[-1]
```

<!-- {
  "Arrays & Hashing": [
    "https://leetcode.com/problems/contains-duplicate/",
    "https://leetcode.com/problems/valid-anagram/",
    "https://leetcode.com/problems/two-sum/",
    "https://leetcode.com/problems/group-anagrams/"
  ]
} -->