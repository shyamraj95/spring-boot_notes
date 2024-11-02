<table class="details-table">
  <!--  <tr><th rowspan="8">Demand Details</th></tr> -->
  <tbody>
    <tr>
      <td><strong>Demand Name:</strong></td>
      <td>{{ demandDetails?.demandName || "N/A" }}</td>
      <td><strong>Project Name:</strong></td>
      <td colspan="3">{{ demandDetails?.project?.projectName || "N/A" }}</td>
    </tr>
    <tr>
      <td><strong>Description:</strong></td>
      <td colspan="5">{{ demandDetails?.project?.description || "N/A" }}</td>
    </tr>
    <tr>
      <td><strong>Due Date:</strong></td>
      <td>{{ demandDetails?.dueDate || "N/A" }}</td>
      <td><strong>New Due Date:</strong></td>
      <td>{{ demandDetails?.newDueDate || "N/A" }}</td>
      <td><strong>Due Date Change Count:</strong></td>
      <td>{{ demandDetails?.dueDateChangeCount || "N/A" }}</td>
    </tr>
    <tr>
      <td><strong>Priority:</strong></td>
      <td>{{ demandDetails?.priority || "N/A" }}</td>
      <td><strong>Status:</strong></td>
      <td>{{ demandDetails?.status || "N/A" }}</td>
      <td><strong>Status Change Date:</strong></td>
      <td>{{ demandDetails?.statusChangeDate || "N/A" }}</td>
    </tr>
    <tr>
      <td><strong>Assign Date:</strong></td>
      <td>{{ demandDetails?.assignDate || "N/A" }}</td>
      <td><strong>Manager:</strong></td>
      <td>{{ demandDetails?.userRoles?.MANAGER || "N/A" }}</td>
      <td><strong>Tech Lead:</strong></td>
      <td>{{ demandDetails?.userRoles?.TECH_LEAD || "N/A" }}</td>
    </tr>
    <tr>
      <td><strong>Developer:</strong></td>
      <td colspan="5">{{ demandDetails?.userRoles?.DEVELOPER || "N/A" }}</td>
    </tr>
    <tr *ngFor="let status of demandDetails?.statusJourney | keyvalue">
      <td>
        <strong>{{ status.key }}:</strong>
      </td>
      <td colspan="5">{{ status.value }}</td>
    </tr>
  </tbody>
</table>
<mat-radio-group [(ngModel)]="selectedCommentType" aria-label="Comment Type">
    <mat-radio-button value="All">All</mat-radio-button>
    <mat-radio-button *ngFor="let type of demandDetails?.comments?.commentType" [value]="type.id">
      {{ type.commentTypeName }}
    </mat-radio-button>
  </mat-radio-group>
<div *ngFor="let comment of demandDetails?.comments">
  <fieldset
    *ngIf="selectedCommentType === 'All' ||
      comment.commentType.commentTypeName === selectedCommentType"
  >
    <legend><strong>Comment Type: </strong> {{ comment.commentType.commentTypeName }}</legend>
    <span><strong>Created By: </strong> {{ comment.createdBy || "N/A" }}</span><br>
    <span><strong>Date: </strong>  <samp>{{ comment.createdAt || "N/A" }}</samp></span><br>
    <span><strong>Comment: </strong>  {{ comment.comment }}</span>
    <section *ngIf="comment.uploads?.length">
      <span><strong>Files: </strong></span>
      <ul>
        <li *ngFor="let file of comment.uploads">
          <a [href]="file.filePath || '#'">{{ file.fileName }}</a>
        </li>
      </ul>
    </section>
  </fieldset>
</div>


  table {
    border-collapse: collapse;
    width: 100%;
    height: max-content;
  }
  
  th, td {
    padding: 8px;
    text-align: left;
    border-bottom: 1px solid #DDD;
  }
  
  tr:hover {background-color: #c9cccc;
}
  
  mat-radio-group {
    display: flex;
    gap: 1rem;
    margin: 1rem 0;
  }
  fieldset {
    -moz-border-radius: 8px;
    -webkit-border-radius: 8px;
    border-radius: 8px;
    border: 1px solid #999;
    padding: 1rem;
    margin-top: 1rem;
   }


     selectedCommentType: string = 'All';
  demandDetails:any;
  filterComments(commentType: string): void {
    this.selectedCommentType = commentType;
  }
constructor() {
  this.demandDetails = demandDetails;
  console.log(this.demandDetails);
  
}

