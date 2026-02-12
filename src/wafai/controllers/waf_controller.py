from typing import Dict
from ..models.request import Request, ThreatAnalysis
from ..services.waf_service import WAFService
from ..services.ai_service import AIService
from ..logger import Logger


class WAFController:
    """WAF Controller - Handles request processing and threat analysis"""
    
    def __init__(self, waf_service: WAFService, ai_service: AIService):
        """
        Initialize WAF Controller
        
        Args:
            waf_service: WAF service instance
            ai_service: AI service instance
        """
        self.waf_service = waf_service
        self.ai_service = ai_service
        self.logger = Logger().get_logger('waf_controller')
    
    def process_request(self, request: Request) -> Dict[str, any]:
        """
        Process HTTP request and perform threat analysis
        
        Args:
            request: HTTP request to process
            
        Returns:
            Response dictionary with analysis results
        """
        self.logger.info(f"Processing request: {request.method} {request.path}")
        
        # Perform WAF analysis
        base_analysis = self.waf_service.analyze_request(request)
        
        # Enhance with AI if enabled
        final_analysis = self.ai_service.enhance_analysis(request, base_analysis)
        
        # Prepare response
        response = {
            'allowed': not final_analysis.is_threat,
            'analysis': final_analysis.to_dict(),
            'request': {
                'method': request.method,
                'path': request.path,
                'ip': request.ip_address,
            }
        }
        
        if final_analysis.is_threat:
            self.logger.warning(f"Request blocked: {final_analysis.threat_type}")
        else:
            self.logger.info("Request allowed")
        
        return response
