"""
Task Management Models
Data models for handling scanning tasks
"""

import uuid
import threading
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, Optional

from utils.logger import logger


class TaskStatus(Enum):
    """Task status enumeration"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskType(Enum):
    """Task type enumeration"""
    PORT_SCAN = "port_scan"
    VULN_SCAN = "vulnerability_scan"
    RECON = "reconnaissance"
    EXPLOIT = "exploit"
    REPORT = "report_generation"


@dataclass
class Task:
    """Task data model"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    task_type: TaskType = TaskType.PORT_SCAN
    target: str = ""
    status: TaskStatus = TaskStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    progress: int = 0
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    params: Dict[str, Any] = field(default_factory=dict)
    
    def start(self):
        """Mark task as started"""
        self.status = TaskStatus.RUNNING
        self.started_at = datetime.now()
        logger.info(f"Task {self.id} started: {self.task_type.value} on {self.target}")
    
    def complete(self, result: Dict[str, Any]):
        """Mark task as completed with result"""
        self.status = TaskStatus.COMPLETED
        self.completed_at = datetime.now()
        self.progress = 100
        self.result = result
        logger.info(f"Task {self.id} completed successfully")
    
    def fail(self, error: str):
        """Mark task as failed with error"""
        self.status = TaskStatus.FAILED
        self.completed_at = datetime.now()
        self.error = error
        logger.error(f"Task {self.id} failed: {error}")
    
    def update_progress(self, progress: int):
        """Update task progress"""
        self.progress = min(100, max(0, progress))
        logger.debug(f"Task {self.id} progress: {self.progress}%")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert task to dictionary"""
        return {
            'id': self.id,
            'type': self.task_type.value,
            'target': self.target,
            'status': self.status.value,
            'created_at': self.created_at.isoformat(),
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'progress': self.progress,
            'result': self.result,
            'error': self.error,
            'params': self.params
        }


class TaskManager:
    """Manages all scanning tasks"""
    
    def __init__(self):
        self.tasks: Dict[str, Task] = {}
        self.lock = threading.Lock()
    
    def create_task(self, task_type: str, target: str, params: Dict[str, Any]) -> Task:
        """Create a new task"""
        try:
            task_type_enum = TaskType(task_type)
        except ValueError:
            raise ValueError(f"Invalid task type: {task_type}")
        
        task = Task(
            task_type=task_type_enum,
            target=target,
            params=params
        )
        
        with self.lock:
            self.tasks[task.id] = task
        
        logger.info(f"Created task {task.id}: {task_type} for {target}")
        return task
    
    def get_task(self, task_id: str) -> Optional[Task]:
        """Get task by ID"""
        with self.lock:
            return self.tasks.get(task_id)
    
    def get_all_tasks(self) -> Dict[str, Task]:
        """Get all tasks"""
        with self.lock:
            return self.tasks.copy()
    
    def delete_task(self, task_id: str) -> bool:
        """Delete task by ID"""
        with self.lock:
            if task_id in self.tasks:
                del self.tasks[task_id]
                logger.info(f"Deleted task {task_id}")
                return True
        return False
    
    def cleanup_completed_tasks(self, max_age_hours: int = 24):
        """Clean up old completed tasks"""
        cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
        
        with self.lock:
            to_delete = []
            for task_id, task in self.tasks.items():
                if (task.status in [TaskStatus.COMPLETED, TaskStatus.FAILED] and 
                    task.completed_at and task.completed_at < cutoff_time):
                    to_delete.append(task_id)
            
            for task_id in to_delete:
                del self.tasks[task_id]
            
            if to_delete:
                logger.info(f"Cleaned up {len(to_delete)} old tasks")


# Global task manager instance
task_manager = TaskManager()
