import React, { useState, useRef } from "react";

export default function App() {
  const [originalText, setOriginalText] = useState("");
  const [displayText, setDisplayText] = useState("");
  const [entities, setEntities] = useState([]);
  const [filter, setFilter] = useState("ALL");
  const entityRefs = useRef({});
  const [redactedKeys, setRedactedKeys] = useState(new Set());

  const runCheck = async () => {
    try {
      const res = await fetch("http://127.0.0.1:8000/check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: originalText }),
      });
      if (!res.ok) {
        throw new Error(`HTTP error! status: ${res.status}`);
      }
      const data = await res.json();
      setEntities(data);
      setDisplayText(originalText);
      setRedactedKeys(new Set()); // reset redactions
    } catch (error) {
      console.error("Failed to fetch PII data:", error);
    }
  };

  const togglePII = (key) => {
    const updated = new Set(redactedKeys);
    if (updated.has(key)) {
      updated.delete(key);
    } else {
      updated.add(key);
    }
    setRedactedKeys(updated);
    applyRedactions(updated);
  };

  const toggleLabel = (label) => {
    const updated = new Set(redactedKeys);
    entities.forEach(e => {
      if (e.label === label) {
        if (updated.has(e.key)) {
          updated.delete(e.key);
        } else {
          updated.add(e.key);
        }
      }
    });
    setRedactedKeys(updated);
    applyRedactions(updated);
  };

  const applyRedactions = (keysToRedact) => {
    // Sort entities in descending order of their start position to avoid index issues
    const sortedEntities = [...entities].sort((a, b) => b.start - a.start);
    let text = originalText;

    sortedEntities.forEach(e => {
      if (keysToRedact.has(e.key)) {
        // Use substring to replace based on indices
        text = text.substring(0, e.start) + e.key + text.substring(e.end);
      }
    });
    setDisplayText(text);
  };

  const handleHighlightClick = (key) => {
    entityRefs.current[key]?.scrollIntoView({ behavior: "smooth", block: "center" });
  };
  
  const renderHighlightedText = () => {
    if (!entities.length) return displayText;

    // Create a new array of objects to manage text chunks and entities
    let textChunks = [{ text: displayText, isEntity: false, key: null }];
    const sortedEntities = [...entities].sort((a, b) => a.start - b.start);

    sortedEntities.forEach(entity => {
      const newChunks = [];
      let entityFound = false;
      const keyOrOriginal = redactedKeys.has(entity.key) ? entity.key : entity.original;

      textChunks.forEach(chunk => {
        if (chunk.isEntity) {
          newChunks.push(chunk);
          return;
        }

        const text = chunk.text;
        const index = text.indexOf(keyOrOriginal);
        
        if (index !== -1) {
          entityFound = true;
          // Push text before the entity
          if (index > 0) {
            newChunks.push({ text: text.substring(0, index), isEntity: false, key: null });
          }
          // Push the entity itself
          newChunks.push({ text: keyOrOriginal, isEntity: true, key: entity.key });
          // Push text after the entity
          if (index + keyOrOriginal.length < text.length) {
            newChunks.push({ text: text.substring(index + keyOrOriginal.length), isEntity: false, key: null });
          }
        } else {
          newChunks.push(chunk);
        }
      });
      textChunks = newChunks;
    });

    return textChunks.map((chunk, index) => {
      if (chunk.isEntity) {
        return (
          <mark
            key={chunk.key}
            className="highlight"
            onClick={() => handleHighlightClick(chunk.key)}
          >
            {chunk.text}
          </mark>
        );
      }
      return chunk.text;
    });
  };

  const filteredEntities =
    filter === "ALL" ? entities : entities.filter((e) => e.label === filter);

  return (
    <div className="container p-8 bg-gray-50 min-h-screen">
      <div className="flex flex-col lg:flex-row gap-8">
        {/* Main Content Area */}
        <div className="main flex-grow w-full lg:w-3/5 p-6 bg-white rounded-xl shadow-lg border border-gray-200">
          <h1 className="text-3xl font-bold mb-4 text-center text-gray-800">PII Detection & Redaction</h1>
          <textarea
            className="w-full h-48 p-4 mb-4 text-gray-700 bg-gray-100 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 transition-shadow"
            placeholder="Paste or type text..."
            value={originalText}
            onChange={(e) => setOriginalText(e.target.value)}
          />
          <button
            onClick={runCheck}
            className="w-full px-4 py-2 text-lg font-semibold text-white bg-blue-600 rounded-lg hover:bg-blue-700 transition-colors shadow-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
          >
            Run PII Detection
          </button>

          <div className="text-display mt-8 p-4 bg-gray-100 rounded-lg border border-gray-300 min-h-[100px] leading-relaxed">
            {renderHighlightedText()}
          </div>
        </div>

        {/* Sidebar */}
        <div className="sidebar w-full lg:w-2/5 p-6 bg-white rounded-xl shadow-lg border border-gray-200">
          <h3 className="text-2xl font-bold mb-4 text-gray-800">Detected PIIs</h3>
          <div className="flex items-center gap-2 mb-4">
            <select
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="flex-grow p-2 text-gray-700 bg-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option>ALL</option>
              {[...new Set(entities.map((e) => e.label))].map((label) => (
                <option key={label}>{label}</option>
              ))}
            </select>
            <button
              onClick={() => toggleLabel(filter)}
              disabled={filter === "ALL"}
              className="px-4 py-2 text-sm font-medium text-white bg-green-500 rounded-lg hover:bg-green-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors focus:outline-none focus:ring-2 focus:ring-green-500 focus:ring-offset-2"
            >
              Toggle Redact All {filter}
            </button>
          </div>
          <ul className="space-y-4 max-h-[500px] overflow-y-auto">
            {filteredEntities.map((e) => (
              <li
                key={e.key}
                ref={(el) => (entityRefs.current[e.key] = el)}
                className="p-4 bg-gray-100 rounded-lg border border-gray-300 shadow-sm"
              >
                <div className="flex justify-between items-start">
                  <span className="text-lg font-bold text-blue-600">{e.key}</span>
                  <span className="bg-blue-200 text-blue-800 text-xs font-semibold px-2 py-1 rounded-full">{e.label}</span>
                </div>
                <div className="text-sm mt-2 text-gray-600">
                  <p><strong>Score:</strong> {(e.score * 100).toFixed(2)}%</p>
                  <p><strong>Original:</strong> {e.original}</p>
                </div>
                <button
                  onClick={() => togglePII(e.key)}
                  className={`mt-3 px-4 py-2 w-full text-sm font-semibold text-white rounded-lg transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2 ${
                    redactedKeys.has(e.key) ? 'bg-red-500 hover:bg-red-600 focus:ring-red-500' : 'bg-green-500 hover:bg-green-600 focus:ring-green-500'
                  }`}
                >
                  {redactedKeys.has(e.key) ? "Unredact" : "Redact"}
                </button>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}
