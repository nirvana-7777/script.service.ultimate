// Simplified FuzzySet implementation for EPG matching
class FuzzySet {
    constructor(arr, useLevenshtein = true, gramSizeLower = 2, gramSizeUpper = 3) {
        this.exactSet = {};
        this.matchDict = {};
        this.items = {};
        this.useLevenshtein = useLevenshtein;
        this.gramSizeLower = gramSizeLower;
        this.gramSizeUpper = gramSizeUpper;

        if (arr) {
            arr.forEach(item => this.add(item));
        }
    }

    add(value) {
        const normalized = this._normalize(value);
        if (this.items[normalized]) return;

        const index = Object.keys(this.items).length;
        this.items[normalized] = [value, 0];

        // Add to exact set for direct matching
        this.exactSet[normalized] = [index, 0];

        // Generate gram keys
        const gramCount = this.gramSizeUpper - this.gramSizeLower + 1;
        for (let gramSize = this.gramSizeLower; gramSize <= this.gramSizeUpper; gramSize++) {
            const grams = this._gramify(normalized, gramSize);
            grams.forEach(gram => {
                if (!this.matchDict[gram]) this.matchDict[gram] = [];
                this.matchDict[gram].push([index, gramCount]);
            });
        }
    }

    get(value) {
        const normalized = this._normalize(value);

        // Check exact match first
        if (this.exactSet[normalized]) {
            const [index, distance] = this.exactSet[normalized];
            return [[1.0, this.items[normalized][0]]];
        }

        const results = [];
        const gramResults = {};
        const minGram = this.gramSizeLower;
        const maxGram = this.gramSizeUpper;

        // Get gram matches
        for (let gramSize = minGram; gramSize <= maxGram; gramSize++) {
            const grams = this._gramify(normalized, gramSize);
            grams.forEach(gram => {
                if (this.matchDict[gram]) {
                    this.matchDict[gram].forEach(([index, gramCount]) => {
                        if (!gramResults[index]) gramResults[index] = 0;
                        gramResults[index] += 1 / gramCount;
                    });
                }
            });
        }

        // Calculate scores
        Object.keys(gramResults).forEach(index => {
            const score = gramResults[index] / this._gramify(normalized, 2).length;
            if (score > 0) {
                results.push([score, this.items[Object.keys(this.items)[index]][0]]);
            }
        });

        // Sort by score descending
        results.sort((a, b) => b[0] - a[0]);

        // Use Levenshtein distance for top results if enabled
        if (this.useLevenshtein && results.length > 0) {
            results.forEach(result => {
                const normalizedItem = this._normalize(result[1]);
                const distance = this._levenshtein(normalized, normalizedItem);
                const maxLen = Math.max(normalized.length, normalizedItem.length);
                result[0] = 1 - (distance / maxLen);
            });
            results.sort((a, b) => b[0] - a[0]);
        }

        return results.slice(0, 5); // Return top 5 matches
    }

    _normalize(str) {
        return str.toLowerCase().replace(/[^\w\s]/g, ' ').replace(/\s+/g, ' ').trim();
    }

    _gramify(str, gramSize) {
        const normalized = this._normalize(str);
        const grams = [];
        for (let i = 0; i < normalized.length - gramSize + 1; i++) {
            grams.push(normalized.substring(i, i + gramSize));
        }
        return grams;
    }

    _levenshtein(a, b) {
        if (a.length === 0) return b.length;
        if (b.length === 0) return a.length;

        const matrix = [];
        for (let i = 0; i <= b.length; i++) {
            matrix[i] = [i];
        }
        for (let j = 0; j <= a.length; j++) {
            matrix[0][j] = j;
        }

        for (let i = 1; i <= b.length; i++) {
            for (let j = 1; j <= a.length; j++) {
                const cost = a[j - 1] === b[i - 1] ? 0 : 1;
                matrix[i][j] = Math.min(
                    matrix[i - 1][j] + 1,
                    matrix[i][j - 1] + 1,
                    matrix[i - 1][j - 1] + cost
                );
            }
        }

        return matrix[b.length][a.length];
    }
}