#!/usr/bin/env python3
"""
Stock Data Module - Fetches stock data using Yahoo Finance API
"""

import sys
import os
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import json

# Add path for data API access
sys.path.append('/opt/.manus/.sandbox-runtime')
from data_api import ApiClient

class StockData:
    def __init__(self):
        """Initialize the StockData class with Yahoo Finance API client"""
        self.client = ApiClient()
        
    def get_stock_history(self, symbol, interval='1d', range='1y'):
        """
        Get historical stock data
        
        Args:
            symbol (str): Stock symbol (e.g., 'AAPL')
            interval (str): Data interval (1m, 2m, 5m, 15m, 30m, 60m, 1d, 1wk, 1mo)
            range (str): Data range (1d, 5d, 1mo, 3mo, 6mo, 1y, 2y, 5y, 10y, ytd, max)
            
        Returns:
            dict: Processed stock data with price history and metadata
        """
        try:
            # Call Yahoo Finance API to get stock chart data
            stock_data = self.client.call_api('YahooFinance/get_stock_chart', 
                                             query={'symbol': symbol, 
                                                   'interval': interval, 
                                                   'range': range,
                                                   'includeAdjustedClose': True})
            
            # Process the response
            if not stock_data or 'chart' not in stock_data or 'result' not in stock_data['chart']:
                return {'error': f"Failed to fetch data for {symbol}"}
            
            result = stock_data['chart']['result'][0]
            
            # Extract metadata
            meta = result['meta']
            
            # Extract timestamp and price data
            timestamps = result['timestamp']
            indicators = result['indicators']
            
            # Get quote data (open, high, low, close, volume)
            quote = indicators['quote'][0]
            
            # Get adjusted close if available
            adjclose = None
            if 'adjclose' in indicators and indicators['adjclose']:
                adjclose = indicators['adjclose'][0]['adjclose']
            
            # Create a dictionary with processed data
            processed_data = {
                'symbol': meta['symbol'],
                'currency': meta.get('currency'),
                'exchange': meta.get('exchangeName'),
                'interval': meta.get('dataGranularity'),
                'range': meta.get('range'),
                'timestamps': timestamps,
                'dates': [datetime.fromtimestamp(ts).strftime('%Y-%m-%d') for ts in timestamps],
                'open': quote.get('open'),
                'high': quote.get('high'),
                'low': quote.get('low'),
                'close': quote.get('close'),
                'volume': quote.get('volume'),
                'adjclose': adjclose,
                'current_price': meta.get('regularMarketPrice'),
                'fifty_two_week_high': meta.get('fiftyTwoWeekHigh'),
                'fifty_two_week_low': meta.get('fiftyTwoWeekLow')
            }
            
            # Calculate additional metrics
            self._calculate_metrics(processed_data)
            
            return processed_data
            
        except Exception as e:
            return {'error': f"Error fetching data for {symbol}: {str(e)}"}
    
    def _calculate_metrics(self, data):
        """
        Calculate additional metrics for stock analysis
        
        Args:
            data (dict): Stock data dictionary to be enhanced with metrics
        """
        if 'close' not in data or not data['close']:
            return
        
        close_prices = data['close']
        
        # Calculate all-time high
        data['all_time_high'] = max(close_prices)
        data['all_time_high_date'] = data['dates'][close_prices.index(data['all_time_high'])]
        
        # Calculate all-time low
        data['all_time_low'] = min(close_prices)
        data['all_time_low_date'] = data['dates'][close_prices.index(data['all_time_low'])]
        
        # Calculate recent drops (last 30 days if available)
        if len(close_prices) > 1:
            # Calculate daily returns
            returns = []
            for i in range(1, len(close_prices)):
                if close_prices[i-1] and close_prices[i]:
                    daily_return = (close_prices[i] - close_prices[i-1]) / close_prices[i-1]
                    returns.append((data['dates'][i], daily_return))
            
            # Find significant drops (daily return < -0.02 or -2%)
            data['significant_drops'] = [(date, round(ret*100, 2)) for date, ret in returns if ret < -0.02]
            
            # Find current price relative to all-time high
            if data['all_time_high'] > 0:
                data['pct_from_ath'] = round((close_prices[-1] - data['all_time_high']) / data['all_time_high'] * 100, 2)
            
    def get_stock_insights(self, symbol):
        """
        Get stock insights and analysis
        
        Args:
            symbol (str): Stock symbol (e.g., 'AAPL')
            
        Returns:
            dict: Stock insights data
        """
        try:
            insights = self.client.call_api('YahooFinance/get_stock_insights', 
                                           query={'symbol': symbol})
            
            return insights
        except Exception as e:
            return {'error': f"Error fetching insights for {symbol}: {str(e)}"}
    
    def detect_drops(self, symbol, threshold=-0.05, days=30):
        """
        Detect significant price drops for a stock
        
        Args:
            symbol (str): Stock symbol
            threshold (float): Drop threshold (default -5%)
            days (int): Number of days to look back
            
        Returns:
            dict: Drop detection results
        """
        # Get daily data for the specified period
        data = self.get_stock_history(symbol, interval='1d', range=f"{days}d")
        
        if 'error' in data:
            return data
        
        drops = []
        if 'close' in data and len(data['close']) > 1:
            close_prices = data['close']
            dates = data['dates']
            
            # Find drops exceeding threshold
            for i in range(1, len(close_prices)):
                if close_prices[i-1] and close_prices[i]:
                    daily_return = (close_prices[i] - close_prices[i-1]) / close_prices[i-1]
                    if daily_return <= threshold:
                        drops.append({
                            'date': dates[i],
                            'previous_close': close_prices[i-1],
                            'close': close_prices[i],
                            'drop_percentage': round(daily_return * 100, 2)
                        })
        
        return {
            'symbol': symbol,
            'threshold': threshold * 100,
            'period_days': days,
            'drops_detected': len(drops),
            'drops': drops
        }
    
    def detect_all_time_highs(self, symbol, range='1y'):
        """
        Detect all-time highs for a stock
        
        Args:
            symbol (str): Stock symbol
            range (str): Data range to analyze
            
        Returns:
            dict: All-time high detection results
        """
        # Get data for the specified range
        data = self.get_stock_history(symbol, interval='1d', range=range)
        
        if 'error' in data:
            return data
        
        highs = []
        if 'close' in data and len(data['close']) > 0:
            close_prices = data['close']
            dates = data['dates']
            
            # Find all-time highs (where price is higher than all previous prices)
            current_high = close_prices[0]
            for i in range(1, len(close_prices)):
                if close_prices[i] and close_prices[i] > current_high:
                    current_high = close_prices[i]
                    highs.append({
                        'date': dates[i],
                        'price': close_prices[i]
                    })
        
        # Check if current price is at or near all-time high
        is_at_ath = False
        pct_from_ath = None
        
        if 'all_time_high' in data and data['current_price']:
            pct_from_ath = round((data['current_price'] - data['all_time_high']) / data['all_time_high'] * 100, 2)
            is_at_ath = pct_from_ath >= -0.5  # Within 0.5% of ATH
        
        return {
            'symbol': symbol,
            'range': range,
            'all_time_high': data.get('all_time_high'),
            'all_time_high_date': data.get('all_time_high_date'),
            'current_price': data.get('current_price'),
            'percent_from_ath': pct_from_ath,
            'is_at_ath': is_at_ath,
            'ath_occurrences': len(highs),
            'ath_history': highs
        }

# Test function
def test_stock_data():
    """Test the StockData class functionality"""
    stock_data = StockData()
    
    # Test with Apple stock
    apple_data = stock_data.get_stock_history('AAPL', range='1y')
    
    # Save results to file
    with open('apple_test_data.json', 'w') as f:
        # Convert numpy values to Python native types for JSON serialization
        serializable_data = {}
        for key, value in apple_data.items():
            if isinstance(value, list) and value and isinstance(value[0], (np.float64, np.int64)):
                serializable_data[key] = [float(x) if x is not None else None for x in value]
            else:
                serializable_data[key] = value
        
        json.dump(serializable_data, f, indent=2)
    
    # Test drop detection
    drops = stock_data.detect_drops('AAPL', threshold=-0.03)
    with open('apple_drops.json', 'w') as f:
        json.dump(drops, f, indent=2)
    
    # Test all-time high detection
    ath = stock_data.detect_all_time_highs('AAPL')
    with open('apple_ath.json', 'w') as f:
        json.dump(ath, f, indent=2)
    
    print("Stock data tests completed. Results saved to JSON files.")

if __name__ == "__main__":
    test_stock_data()
