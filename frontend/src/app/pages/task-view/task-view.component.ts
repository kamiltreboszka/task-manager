import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Params, Router } from '@angular/router';
import { List } from 'src/app/models/list.model';
import { Task } from 'src/app/models/task.model';
import { TaskService } from 'src/app/task.service';
import { AuthService } from 'src/app/auth.service';

@Component({
  selector: 'app-task-view',
  templateUrl: './task-view.component.html',
  styleUrls: ['./task-view.component.scss']
})
export class TaskViewComponent implements OnInit {

  lists: List[];
  tasks: Task[];

  selectedListId: string;

  constructor(private taskService: TaskService, private authService: AuthService, private route:ActivatedRoute, private router: Router) { }

  ngOnInit(): void {
    this.route.params.subscribe(
      (params: Params)=>{
        if(params.listId){
          this.selectedListId = params.listId;
          this.taskService.getTask(params.listId).subscribe((tasks: Task[]) => {
          this.tasks = tasks;
        })
      } else {
        this.tasks = undefined;
      }
      }
    )
  
  this.taskService.getLists().subscribe((lists: List[])=>{
    this.lists = lists;
  })
  }

  onTaskClick(task: Task) {
    //zmiana zadania na ukonczone
    this.taskService.complete(task).subscribe(()=>{
      console.log("Ukonczone sukcesem");
      //zadanie zostalo oznaczone jako ukonczone
      task.completed = !task.completed;
    })
  }

  onDeleteListClick() {
    this.taskService.deleteList(this.selectedListId).subscribe((res: any) => {
      this.router.navigate(['/lists']);
      console.log(res);
    })
  }

  onDeleteTaskClick(id: string) {
    this.taskService.deleteTask(this.selectedListId, id).subscribe((res: any) => {
      this.tasks = this.tasks.filter(val => val._id !== id);
      console.log(res);
    })
  }

  onLogoutClick(){
    this.authService.logout();
  }

}


