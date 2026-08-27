import { useState } from 'react';
import { Search } from 'lucide-react';
import { EmptyState } from '../common/Atoms';

export function SearchPage() {
  const [simType, setSimType] = useState('ssdeep');
  const [query, setQuery] = useState('');
  const [searched, setSearched] = useState(false);

  const handleSearch = () => {
    if (query.trim()) setSearched(true);
  };

  return (
    <div>
      <section className="search-page-hero">
        <h1>Similarity search</h1>
        <div className="similarity-search">
          <select value={simType} onChange={e => setSimType(e.target.value)} aria-label="Similarity metric">
            <option value="ssdeep">ssdeep</option>
            <option value="dexofuzzy">dexofuzzy</option>
            <option value="func_hash">func_hash</option>
            <option value="signer">signer</option>
            <option value="icon_phash">icon pHash</option>
          </select>
          <input
            placeholder="Enter hash, fingerprint or pattern..."
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') handleSearch(); }}
            aria-label="Search query"
          />
          <button onClick={handleSearch} aria-label="Run search" type="button">
            <Search size={18} style={{ margin: '0 auto' }} />
          </button>
        </div>
      </section>

      <main className="main">
        <h2 className="section-title">Results</h2>
        {searched ? (
          <EmptyState
            title="No matching samples found"
            message={`No samples matched fingerprint search for '${query}' with type '${simType}'.`}
          />
        ) : (
          <EmptyState
            title="Enter a query to search"
            message="Search across persistent FraudDNA fingerprints, SSDeep hashes and fuzzy method signatures."
          />
        )}
      </main>
    </div>
  );
}
