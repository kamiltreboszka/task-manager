import { Injectable } from '@angular/core';
import { Task } from './models/task.model';
import { WebRequestService } from './web-request.service';

@Injectable({
  providedIn: 'root'
})
export class TaskService {

  constructor(private webReqService: WebRequestService) { }

  getLists(){
    return this.webReqService.get('lists');
  }

  createList(title: string){
    //chcemy wysłac zapytanie w celu stworzenia listy
    return this.webReqService.post('lists', {title});
  }

  updateList(id: string, title: string) {
    // chcemy wysłac zapytanie w celu edycji listy
    return this.webReqService.patch(`lists/${id}`, { title });
  }

  updateTask(listId: string, taskId: string, title: string) {
    //chcemy wysłac zapytanie w celu edycji zadania
    return this.webReqService.patch(`lists/${listId}/tasks/${taskId}`, { title });
  }

  deleteTask(listId: string, taskId: string) {
    return this.webReqService.delete(`lists/${listId}/tasks/${taskId}`);
  }

  deleteList(id: string) {
    return this.webReqService.delete(`lists/${id}`);
  }

  getTask(listId: string){
    return this.webReqService.get(`lists/${listId}/tasks`);
  }

  createTask(title: string, listId: string){
    //chcemy wysłac zapytanie w celu stworzenia zadania
    return this.webReqService.post(`lists/${listId}/tasks`,{title});
  }

  complete(task: Task){
    return this.webReqService.patch(`lists/${task._listId}/tasks/${task._id}`, {
      completed: !task.completed
    });
  }
}
