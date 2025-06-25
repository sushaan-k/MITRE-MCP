from fastapi import FastAPI, HTTPException, Request
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from datetime import datetime
import uvicorn

from threat_analyzer import ThreatAnalyzer
from mitre_attack import MitreAttackFramework

app = FastAPI(
    title="MITRE MCP Threat Intelligence API",
    description="Threat intelligence framework with MITRE ATT&CK mapping",
    version="1.0.0"
)

threat_analyzer = ThreatAnalyzer()
mitre_framework = MitreAttackFramework()
templates = Jinja2Templates(directory="templates")

class ThreatAnalysisRequest(BaseModel):
    content: str
    source: Optional[str] = "Web Interface"

class KeywordSearchRequest(BaseModel):
    keywords: List[str]
    min_confidence: Optional[float] = 0.3


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Home page with threat analysis interface"""
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/api/analyze")
async def analyze_threat(request: ThreatAnalysisRequest) -> Dict[str, Any]:
    """Analyze threat intelligence report"""
    try:
        if not request.content.strip():
            raise HTTPException(status_code=400, detail="Empty content provided")
        
        # Perform analysis
        analysis = threat_analyzer.analyze_threat_report(request.content, request.source)
        
        # Convert to JSON-serializable format
        result = {
            "analysis_id": analysis.id,
            "report": {
                "id": analysis.report.id,
                "title": analysis.report.title,
                "description": analysis.report.description,
                "severity": analysis.report.severity.value,
                "source": analysis.report.source,
                "timestamp": analysis.report.timestamp.isoformat(),
                "indicators": [
                    {
                        "id": ind.id,
                        "type": ind.type,
                        "value": ind.value,
                        "severity": ind.severity.value,
                        "confidence": ind.confidence,
                        "tags": ind.tags
                    } for ind in analysis.report.indicators
                ]
            },
            "mitre_mappings": [
                {
                    "id": mapping.id,
                    "tactic_id": mapping.tactic_id,
                    "technique_id": mapping.technique_id,
                    "confidence": mapping.confidence,
                    "evidence": mapping.evidence,
                    "analyst_notes": mapping.analyst_notes
                } for mapping in analysis.mappings
            ],
            "risk_score": analysis.risk_score,
            "recommendations": analysis.recommendations,
            "analysis_timestamp": analysis.analysis_timestamp.isoformat(),
            "analyst": analysis.analyst
        }
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.post("/api/search/techniques")
async def search_techniques(request: KeywordSearchRequest) -> Dict[str, Any]:
    """Search MITRE ATT&CK techniques by keywords"""
    try:
        if not request.keywords:
            raise HTTPException(status_code=400, detail="No keywords provided")
        
        # Search techniques
        technique_matches = mitre_framework.search_techniques_by_keywords(request.keywords)
        
        # Filter and format results
        results = []
        for technique, confidence in technique_matches:
            if confidence >= request.min_confidence:
                # Get tactic names
                tactic_names = []
                for tactic_id in technique.tactic_ids:
                    tactic = mitre_framework.get_tactic_by_id(tactic_id)
                    if tactic:
                        tactic_names.append(tactic.name)
                
                results.append({
                    "technique_id": technique.id,
                    "name": technique.name,
                    "description": technique.description,
                    "confidence": confidence,
                    "tactic_ids": technique.tactic_ids,
                    "tactic_names": tactic_names,
                    "platforms": technique.platforms,
                    "data_sources": technique.data_sources,
                    "mitigations": technique.mitigations
                })
        
        # Sort by confidence
        results.sort(key=lambda x: x["confidence"], reverse=True)
        
        return {
            "keywords": request.keywords,
            "min_confidence": request.min_confidence,
            "results_count": len(results),
            "results": results[:20]  # Limit to top 20
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")


@app.get("/api/tactics")
async def get_all_tactics() -> Dict[str, Any]:
    """Get all MITRE ATT&CK tactics"""
    try:
        tactics = mitre_framework.get_all_tactics()
        
        result = {
            "tactics_count": len(tactics),
            "tactics": [
                {
                    "id": tactic.id,
                    "name": tactic.name,
                    "description": tactic.description,
                    "external_id": tactic.external_id
                } for tactic in tactics
            ]
        }
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get tactics: {str(e)}")


@app.get("/api/tactics/{tactic_id}")
async def get_tactic_details(tactic_id: str) -> Dict[str, Any]:
    """Get details for a specific tactic"""
    try:
        tactic = mitre_framework.get_tactic_by_id(tactic_id)
        if not tactic:
            raise HTTPException(status_code=404, detail=f"Tactic {tactic_id} not found")
        
        # Get associated techniques
        techniques = mitre_framework.get_techniques_by_tactic(tactic_id)
        
        result = {
            "tactic": {
                "id": tactic.id,
                "name": tactic.name,
                "description": tactic.description,
                "external_id": tactic.external_id
            },
            "techniques_count": len(techniques),
            "techniques": [
                {
                    "id": tech.id,
                    "name": tech.name,
                    "description": tech.description,
                    "platforms": tech.platforms
                } for tech in techniques
            ]
        }
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get tactic details: {str(e)}")


@app.get("/api/techniques/{technique_id}")
async def get_technique_details(technique_id: str) -> Dict[str, Any]:
    """Get details for a specific technique"""
    try:
        technique = mitre_framework.get_technique_by_id(technique_id)
        if not technique:
            raise HTTPException(status_code=404, detail=f"Technique {technique_id} not found")
        
        # Get associated tactics
        tactics = []
        for tactic_id in technique.tactic_ids:
            tactic = mitre_framework.get_tactic_by_id(tactic_id)
            if tactic:
                tactics.append({
                    "id": tactic.id,
                    "name": tactic.name,
                    "description": tactic.description
                })
        
        result = {
            "technique": {
                "id": technique.id,
                "name": technique.name,
                "description": technique.description,
                "platforms": technique.platforms,
                "data_sources": technique.data_sources,
                "mitigations": technique.mitigations,
                "sub_techniques": technique.sub_techniques
            },
            "tactics": tactics
        }
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get technique details: {str(e)}")


@app.get("/api/health")
async def health_check() -> Dict[str, str]:
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    }


def main():
    print("Starting MITRE MCP Web Interface...")
    print("Server: http://localhost:8000")
    print("API Docs: http://localhost:8000/docs")

    uvicorn.run(
        "web_interface:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )


if __name__ == "__main__":
    main()
